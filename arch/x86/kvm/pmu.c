#include <linux/types.h>
#include <linux/kvm_host.h>
#include <linux/perf_event.h>
#include <asm/perf_event.h>
#include "x86.h"
#include "cpuid.h"
#include "lapic.h"
#include "pmu.h"

static struct x86_pmu_capability* kvm_pmu_get_real_pmu_capability(void)
{
	struct x86_pmu_capability *cap = NULL;
	cap = kmalloc(sizeof(struct x86_pmu_capability), GFP_KERNEL);
	if(likely(cap)) {
		perf_get_x86_pmu_capability(cap);
	}
	printk(KERN_NOTICE "kvm_pmu_get_real_pmu_capability\n");
	return cap;
}

static void kvm_pmu_destroy_cap(struct kvm_pmu *pmu)
{
	if (likely(pmu->cap)) {
		kfree(pmu->cap);
	}
	pmu->cap = NULL;
	printk(KERN_NOTICE "kvm_pmu_destroy_cap\n");
}
static inline unsigned long __pmu_vmcs_readl(unsigned long field)
{
	unsigned long value;

	asm volatile (__pmu_ex_clear(ASM_VMX_VMREAD_RDX_RAX, "%0")
			: "=a"(value) : "d"(field) : "cc");
	return value;
}

static inline u16 pmu_vmcs_read16(unsigned long field)
{
	return __pmu_vmcs_readl(field);
}

static inline u32 pmu_vmcs_read32(unsigned long field)
{
	return __pmu_vmcs_readl(field);
}

static inline u64 pmu_vmcs_read64(unsigned long field)
{
#ifdef CONFIG_X86_64
	return __pmu_vmcs_readl(field);
#else
	return __pmu_vmcs_readl(field) | ((u64)__pmu_vmcs_readl(field+1) << 32);
#endif
}

static inline void __pmu_vmcs_writel(unsigned long field, unsigned long value)
{
	u8 error;
	asm volatile (__pmu_ex(ASM_VMX_VMWRITE_RAX_RDX) "; setna %0"
			: "=q"(error) : "a"(value), "d"(field) : "cc");
}

static inline void pmu_vmcs_write16(unsigned long field, u16 value)
{
	__pmu_vmcs_writel(field, value);
}

static inline void pmu_vmcs_write32(unsigned long field, u32 value)
{
	__pmu_vmcs_writel(field, value);
}

static inline void pmu_vmcs_write64(unsigned long field, u64 value)
{
	__pmu_vmcs_writel(field, value);
#ifndef CONFIG_X86_64
	asm volatile ("");
	__pmu_vmcs_writel(field+1, value >> 32);
#endif
}

static struct kvm_arch_event_perf_mapping {
	u8 eventsel;
	u8 unit_mask;
	unsigned event_type;
	bool inexact;
} arch_events[] = {
	[0] = { 0x3c, 0x00, PERF_COUNT_HW_CPU_CYCLES },
	[1] = { 0xc0, 0x00, PERF_COUNT_HW_INSTRUCTIONS },
	[2] = { 0x3c, 0x01, PERF_COUNT_HW_BUS_CYCLES  },
	[3] = { 0x2e, 0x4f, PERF_COUNT_HW_CACHE_REFERENCES },
	[4] = { 0x2e, 0x41, PERF_COUNT_HW_CACHE_MISSES },
	[5] = { 0xc4, 0x00, PERF_COUNT_HW_BRANCH_INSTRUCTIONS },
	[6] = { 0xc5, 0x00, PERF_COUNT_HW_BRANCH_MISSES },
	[7] = { 0x00, 0x30, PERF_COUNT_HW_REF_CPU_CYCLES },
};

int fixed_pmc_events[] = {1, 0, 7};

static bool pmc_is_gp(struct kvm_pmc *pmc)
{
	return pmc->type == KVM_PMC_GP;
}

static u64 change_data(struct kvm_pmc *pmc, u64 old)
{
	int bit_width, n = 0;
	u64 mask, flag = old;
	struct kvm_pmu *pmu = &pmc->vcpu->arch.pmu;
	while(flag) {
		flag >>= 1;
		n++;
	}
	if (pmc_is_gp(pmc))
		bit_width = pmu->v_eax.split.bit_width;
	else
		bit_width = pmu->v_edx.split.bit_width_fixed;
	n = max(bit_width, n);
	mask = (((1ULL << (64 - n)) - 1ULL) << n);
	return old | mask;
}

static inline u64 pmc_bitmask(struct kvm_pmc *pmc)
{
	struct kvm_pmu *pmu = &pmc->vcpu->arch.pmu;

	return pmu->counter_bitmask[pmc->type];
}

static inline bool pmc_enabled(struct kvm_pmc *pmc)
{
	struct kvm_pmu *pmu = &pmc->vcpu->arch.pmu;
	return test_bit(pmc->idx, (unsigned long *)&pmu->global_ctrl);
}

static inline struct kvm_pmc *get_gp_pmc(struct kvm_pmu *pmu, u32 msr,
		u32 base)
{
	if (msr >= base && msr < base + pmu->nr_arch_gp_counters)
		return &pmu->gp_counters[msr - base];
	return NULL;
}

static inline struct kvm_pmc *get_fixed_pmc(struct kvm_pmu *pmu, u32 msr)
{
	int base = MSR_CORE_PERF_FIXED_CTR0;
	if (msr >= base && msr < base + pmu->nr_arch_fixed_counters)
		return &pmu->fixed_counters[msr - base];
	return NULL;
}

static inline struct kvm_pmc *get_fixed_pmc_idx(struct kvm_pmu *pmu, int idx)
{
	return get_fixed_pmc(pmu, MSR_CORE_PERF_FIXED_CTR0 + idx);
}

static struct kvm_pmc *global_idx_to_pmc(struct kvm_pmu *pmu, int idx)
{
	if (idx < INTEL_PMC_IDX_FIXED)
		return get_gp_pmc(pmu, MSR_P6_EVNTSEL0 + idx, MSR_P6_EVNTSEL0);
	else
		return get_fixed_pmc_idx(pmu, idx - INTEL_PMC_IDX_FIXED);
}

static void trigger_pmi(struct irq_work *irq_work)
{
	struct kvm_pmu *pmu = container_of(irq_work, struct kvm_pmu,
			irq_work);
	struct kvm_vcpu *vcpu = container_of(pmu, struct kvm_vcpu,
			arch.pmu);

	kvm_deliver_pmi(vcpu);
}

static void kvm_perf_overflow(struct perf_event *perf_event,
		struct perf_sample_data *data,
		struct pt_regs *regs)
{
	struct kvm_pmc *pmc = perf_event->overflow_handler_context;
	struct kvm_pmu *pmu = &pmc->vcpu->arch.pmu;
	printk(KERN_NOTICE "kvm_perf_overflow\n");
	if (!test_and_set_bit(pmc->idx, (unsigned long *)&pmu->reprogram_pmi)) {
		__set_bit(pmc->idx, (unsigned long *)&pmu->global_status);
		kvm_make_request(KVM_REQ_PMU, pmc->vcpu);
	}
}

static void kvm_perf_overflow_intr(struct perf_event *perf_event,
		struct perf_sample_data *data, struct pt_regs *regs)
{
	struct kvm_pmc *pmc = perf_event->overflow_handler_context;
	struct kvm_pmu *pmu = &pmc->vcpu->arch.pmu;
	printk(KERN_NOTICE "kvm_perf_overflow_intr\n");
	if (!test_and_set_bit(pmc->idx, (unsigned long *)&pmu->reprogram_pmi)) {
		__set_bit(pmc->idx, (unsigned long *)&pmu->global_status);
		kvm_make_request(KVM_REQ_PMU, pmc->vcpu);
		if (!kvm_is_in_guest()) {
			printk(KERN_NOTICE "irq_work_queue\n");
			irq_work_queue(&pmc->vcpu->arch.pmu.irq_work);
		}
		else
			kvm_make_request(KVM_REQ_PMI, pmc->vcpu);
	}
}

static u64 read_pmc(struct kvm_pmc *pmc)
{
	u64 counter, enabled, running;

	counter = pmc->counter;

	if (pmc->perf_event)
		counter += perf_event_read_value(pmc->perf_event,
				&enabled, &running);

	return counter & pmc_bitmask(pmc);
}
static void disable_counter(struct kvm_pmc *pmc)
{
	if (pmc->perf_event) {
		pmc->counter = read_pmc(pmc);
		perf_event_disable(pmc->perf_event);
	}
}

static void kvm_pmc_counter_set(struct kvm_pmc *pmc, bool flag)
{
	pmc->counter_set = flag;
}

static void enable_counter(struct kvm_pmc *pmc)
{
	if (pmc->perf_event) {
		pmc->counter = read_pmc(pmc);
		perf_event_enable(pmc->perf_event);
		if (pmc->perf_event->state != PERF_EVENT_STATE_ACTIVE)
			printk(KERN_NOTICE "enable_counter failed\n");
	}
}

static void stop_counter(struct kvm_pmc *pmc)
{
	if (pmc->perf_event) {
		pmc->counter = read_pmc(pmc);
		perf_event_release_kernel(pmc->perf_event);
		pmc->perf_event = NULL;
	}
}

static void reprogram_counter(struct kvm_pmc *pmc, u32 type,
		unsigned config, bool exclude_user, bool exclude_kernel,
		bool intr, bool in_tx, bool in_tx_cp)
{
	struct perf_event *event;
	struct perf_event_attr attr = {
		.type = type,
		.size = sizeof(attr),
		.pinned = true,
		.exclude_idle = true,
		.exclude_host = 1,
		.exclude_hv = 1,
		.exclude_user = exclude_user,
		.exclude_kernel = exclude_kernel,
		.config = config,
	};
	if (in_tx)
		attr.config |= HSW_IN_TX;
	if (in_tx_cp)
		attr.config |= HSW_IN_TX_CHECKPOINTED;

	attr.sample_period = (-pmc->counter) & pmc_bitmask(pmc);
	printk(KERN_NOTICE "attr.sample_period = %llx\n", attr.sample_period);

	event = perf_event_create_kernel_counter(&attr, -1, current,
			intr ? kvm_perf_overflow_intr :
			kvm_perf_overflow, pmc);
	if (IS_ERR(event)) {
		printk_once("kvm: pmu event creation failed %ld\n",
				PTR_ERR(event));
		return;
	}

	pmc->perf_event = event;
	clear_bit(pmc->idx, (unsigned long*)&pmc->vcpu->arch.pmu.reprogram_pmi);
}

static unsigned find_arch_event(struct kvm_pmu *pmu, u8 event_select,
		u8 unit_mask)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(arch_events); i++)
		if (arch_events[i].eventsel == event_select
				&& arch_events[i].unit_mask == unit_mask
				&& (pmu->available_event_types & (1 << i)))
			break;

	if (i == ARRAY_SIZE(arch_events))
		return PERF_COUNT_HW_MAX;

	return arch_events[i].event_type;
}

static void reprogram_gp_counter(struct kvm_pmc *pmc, u64 eventsel)
{
	unsigned config, type = PERF_TYPE_RAW;
	u8 event_select, unit_mask;

	if (eventsel & ARCH_PERFMON_EVENTSEL_PIN_CONTROL)
		printk_once("kvm pmu: pin control bit is ignored\n");

	pmc->eventsel = eventsel;

	if (!(eventsel & ARCH_PERFMON_EVENTSEL_ENABLE) || !pmc_enabled(pmc)) {
		printk(KERN_NOTICE "disable_gp_counter\n");
		disable_counter(pmc);
		return;
	}
	else {
		if(pmc->perf_event && !pmc->counter_set) {
			printk(KERN_NOTICE "enable_gp_counter\n");
			enable_counter(pmc);
			return;
		}
	}

	stop_counter(pmc);
	kvm_pmc_counter_set(pmc, false);

	event_select = eventsel & ARCH_PERFMON_EVENTSEL_EVENT;
	unit_mask = (eventsel & ARCH_PERFMON_EVENTSEL_UMASK) >> 8;

	if (!(eventsel & (ARCH_PERFMON_EVENTSEL_EDGE |
					ARCH_PERFMON_EVENTSEL_INV |
					ARCH_PERFMON_EVENTSEL_CMASK |
					HSW_IN_TX |
					HSW_IN_TX_CHECKPOINTED))) {
		config = find_arch_event(&pmc->vcpu->arch.pmu, event_select,
				unit_mask);
		if (config != PERF_COUNT_HW_MAX)
			type = PERF_TYPE_HARDWARE;
	}

	if (type == PERF_TYPE_RAW)
		config = eventsel & X86_RAW_EVENT_MASK;

	reprogram_counter(pmc, type, config,
			!(eventsel & ARCH_PERFMON_EVENTSEL_USR),
			!(eventsel & ARCH_PERFMON_EVENTSEL_OS),
			eventsel & ARCH_PERFMON_EVENTSEL_INT,
			(eventsel & HSW_IN_TX),
			(eventsel & HSW_IN_TX_CHECKPOINTED));
}

static void reprogram_fixed_counter(struct kvm_pmc *pmc, u8 en_pmi, int idx)
{
	unsigned en = en_pmi & 0x3;
	bool pmi = en_pmi & 0x8;


	if (!en || !pmc_enabled(pmc)) {
		printk(KERN_NOTICE "disable_fixed_counter\n");
		disable_counter(pmc);
		return;
	}
	else {
		if(pmc->perf_event && !pmc->counter_set) {
			printk(KERN_NOTICE "enable_fixed_counter\n");
			enable_counter(pmc);
			return;
		}
	}

	stop_counter(pmc);
	kvm_pmc_counter_set(pmc, false);

	reprogram_counter(pmc, PERF_TYPE_HARDWARE,
			arch_events[fixed_pmc_events[idx]].event_type,
			!(en & 0x2), /* exclude user */
			!(en & 0x1), /* exclude kernel */
			pmi, false, false);
}

static inline u8 fixed_en_pmi(u64 ctrl, int idx)
{
	return (ctrl >> (idx * 4)) & 0xf;
}

static void reprogram_fixed_counters(struct kvm_pmu *pmu, u64 data)
{
	int i;

	for (i = 0; i < pmu->nr_arch_fixed_counters; i++) {
		u8 en_pmi = fixed_en_pmi(data, i);
		struct kvm_pmc *pmc = get_fixed_pmc_idx(pmu, i);

		if (fixed_en_pmi(pmu->fixed_ctr_ctrl, i) == en_pmi)
			continue;

		reprogram_fixed_counter(pmc, en_pmi, i);
	}

	pmu->fixed_ctr_ctrl = data;
}

static void reprogram_idx(struct kvm_pmu *pmu, int idx)
{
	struct kvm_pmc *pmc = global_idx_to_pmc(pmu, idx);

	if (!pmc)
		return;

	if (pmc_is_gp(pmc))
		reprogram_gp_counter(pmc, pmc->eventsel);
	else {
		int fidx = idx - INTEL_PMC_IDX_FIXED;
		reprogram_fixed_counter(pmc,
				fixed_en_pmi(pmu->fixed_ctr_ctrl, fidx), fidx);
	}
}

static void global_ctrl_changed(struct kvm_pmu *pmu, u64 data)
{
	int bit;
	struct kvm_pmc *pmc;
	u64 diff = pmu->global_ctrl ^ data;

	pmu->global_ctrl = data;

	for_each_set_bit(bit, (unsigned long *)&diff, X86_PMC_IDX_MAX) {
		if(test_bit(bit, (unsigned long *)&data))
			reprogram_idx(pmu, bit);
		else {
			pmc = global_idx_to_pmc(pmu, bit);
			stop_counter(pmc);
		}
	}
}

static void kvm_pmu_freeze_perfmon_on_pmi(struct kvm_vcpu *vcpu)
{
	struct kvm_pmu *pmu = &vcpu->arch.pmu;
	u64 data = 0;
	if ((pmu->version > 1) && (pmu->freeze_perfmon_on_pmi)) {
		if ((pmu->global_ctrl != data) && !(data & pmu->global_ctrl_mask)) {
			printk(KERN_NOTICE "kvm_pmu_freeze_perfmon_on_pmi\n");
			global_ctrl_changed(pmu, data);
		}
	}
}

static void kvm_pmu_freeze_lbrs_on_pmi(struct kvm_vcpu *vcpu)
{
	struct kvm_pmu *pmu = &vcpu->arch.pmu;
	u32 debugctl_msr;
	if ((pmu->version > 1) && (pmu->version <= 3) && (pmu->freeze_lbrs_on_pmi)) {
		printk(KERN_NOTICE "kvm_pmu_freeze_lbrs_on_pmi\n");
		pmu->debugctl_lbr = 0;
		debugctl_msr = pmu_vmcs_read32(GUEST_IA32_DEBUGCTL);
		clear_bit(0, (unsigned long *)&debugctl_msr);
		pmu_vmcs_write32(GUEST_IA32_DEBUGCTL, debugctl_msr);
	}
}

void kvm_pmu_set_debugctl_lbr(struct kvm_vcpu * vcpu, bool flag)
{
	u32 debugctl_msr;
	debugctl_msr = pmu_vmcs_read32(GUEST_IA32_DEBUGCTL);
	if (flag)
		__set_bit(0, (unsigned long *)&debugctl_msr);
	else
		clear_bit(0, (unsigned long *)&debugctl_msr);
	pmu_vmcs_write32(GUEST_IA32_DEBUGCTL, debugctl_msr);

}

bool kvm_pmu_msr(struct kvm_vcpu *vcpu, u32 msr)
{
	struct kvm_pmu *pmu = &vcpu->arch.pmu;
	int ret;

	switch (msr) {
		case MSR_CORE_PERF_FIXED_CTR_CTRL:
		case MSR_CORE_PERF_GLOBAL_STATUS:
		case MSR_CORE_PERF_GLOBAL_CTRL:
		case MSR_CORE_PERF_GLOBAL_OVF_CTRL:
			ret = pmu->version > 1;
			break;
		default:
			ret = get_gp_pmc(pmu, msr, MSR_IA32_PERFCTR0)
				|| get_gp_pmc(pmu, msr, MSR_P6_EVNTSEL0)
				|| get_fixed_pmc(pmu, msr);
			break;
	}
	return ret;
}

int kvm_pmu_get_msr(struct kvm_vcpu *vcpu, u32 index, u64 *data)
{
	struct kvm_pmu *pmu = &vcpu->arch.pmu;
	struct kvm_pmc *pmc;

	switch (index) {
		case MSR_CORE_PERF_FIXED_CTR_CTRL:
			*data = pmu->fixed_ctr_ctrl;
			printk(KERN_NOTICE "kvm_pmu_get_msr: index = %x FIXED_CTR_CTRL, data = %llx", index, *data);
			return 0;
		case MSR_CORE_PERF_GLOBAL_STATUS:
			*data = pmu->global_status;
			printk(KERN_NOTICE "kvm_pmu_get_msr: index = %x GLOBAL_STATUS, data = %llx", index, *data);
			return 0;
		case MSR_CORE_PERF_GLOBAL_CTRL:
			*data = pmu->global_ctrl;
			printk(KERN_NOTICE "kvm_pmu_get_msr: index = %x GLOBAL_CTRL, data = %llx", index, *data);
			return 0;
		case MSR_CORE_PERF_GLOBAL_OVF_CTRL:
			*data = pmu->global_ovf_ctrl;
			printk(KERN_NOTICE "kvm_pmu_get_msr: index = %x GLOBAL_OVF_CTRL, data = %llx", index, *data);
			return 0;
		default:
			if ((pmc = get_gp_pmc(pmu, index, MSR_IA32_PERFCTR0)) ||
					(pmc = get_fixed_pmc(pmu, index))) {
				*data = read_pmc(pmc);
				printk(KERN_NOTICE "kvm_pmu_get_msr: index = %x, data = %llx", index, *data);
				return 0;
			} else if ((pmc = get_gp_pmc(pmu, index, MSR_P6_EVNTSEL0))) {
				*data = pmc->eventsel;
				printk(KERN_NOTICE "kvm_pmu_get_msr: index = %x, data = %llx", index, *data);
				return 0;
			}
	}
	return 1;
}

int kvm_pmu_set_msr(struct kvm_vcpu *vcpu, struct msr_data *msr_info)
{
	struct kvm_pmu *pmu = &vcpu->arch.pmu;
	struct kvm_pmc *pmc;
	u32 index = msr_info->index;
	u64 data = msr_info->data;

	switch (index) {
		case MSR_CORE_PERF_FIXED_CTR_CTRL:
			printk(KERN_NOTICE "kvm_pmu_set_msr: index = %x FIXED_CTR_CTRL, data = %llx\n", index, data);
			if (data & MSR_ARCH_PERFMON_FIXED_CTR_CTRL_ANY) {
					printk(KERN_NOTICE "clear FIXED_CTR_CTRL ANY_THREAD bit\n");
					data &= MSR_ARCH_PERFMON_FIXED_CTR_CTRL_ANY_MASK;
			}
			if (pmu->fixed_ctr_ctrl == data)
				return 0;
			if (!(data & 0xfffffffffffff444ull)) {
				reprogram_fixed_counters(pmu, data);
				return 0;
			}
			break;
		case MSR_CORE_PERF_GLOBAL_STATUS:
			printk(KERN_NOTICE "kvm_pmu_set_msr: index = %x GLOBAL_STATUS, data = %llx\n", index, data);
			if (msr_info->host_initiated) {
				pmu->global_status = data;
				return 0;
			}
			break;
		case MSR_CORE_PERF_GLOBAL_CTRL:
			printk(KERN_NOTICE "kvm_pmu_set_msr: index = %x GLOBAL_CTRL, data = %llx\n", index, data);
			if (pmu->global_ctrl == data)
				return 0;
			if (!(data & pmu->global_ctrl_mask)) {
				global_ctrl_changed(pmu, data);
				return 0;
			}
			break;
		case MSR_CORE_PERF_GLOBAL_OVF_CTRL:
			printk(KERN_NOTICE "kvm_pmu_set_msr: index = %x GLOBAL_OVF_CTRL, data = %llx\n", index, data);
			if (!(data & (pmu->global_ctrl_mask & ~(3ull<<62)))) {
				if (!msr_info->host_initiated)
					pmu->global_status &= ~data;
				pmu->global_ovf_ctrl = data;
				return 0;
			}
			break;
		default:
			printk(KERN_NOTICE "kvm_pmu_set_msr: index = %x, data = %016llx\n", index, data);
			if ((pmc = get_gp_pmc(pmu, index, MSR_IA32_PERFCTR0)) ||
					(pmc = get_fixed_pmc(pmu, index))) {
				if (likely(!msr_info->host_initiated)) {
					//data = (s64)(s32)data;
					if (likely(pmc->eventsel || !pmc_is_gp(pmc))) {
						data = change_data(pmc, data);
					}
				}
				pmc->counter += data - read_pmc(pmc);
				kvm_pmc_counter_set(pmc, true);
				printk(KERN_NOTICE "kvm_pmu_set_msr: index = %x,  res = %016llx\n", index, pmc->counter);
				return 0;
			} else if ((pmc = get_gp_pmc(pmu, index, MSR_P6_EVNTSEL0))) {
				if (data & ARCH_PERFMON_EVENTSEL_ANY) {
					printk(KERN_NOTICE "clear gp eventsel ANY_THREAD bit\n");
					data &= ARCH_PERFMON_EVENTSEL_ANY_MASK;
				}
				if (data == pmc->eventsel)
					return 0;
				if (!(data & pmu->reserved_bits)) {
					reprogram_gp_counter(pmc, data);
					return 0;
				}
			}
	}
	return 1;
}

int kvm_pmu_check_pmc(struct kvm_vcpu *vcpu, unsigned pmc)
{
	struct kvm_pmu *pmu = &vcpu->arch.pmu;
	bool fixed = pmc & (1u << 30);
	pmc &= ~(3u << 30);
	return (!fixed && pmc >= pmu->nr_arch_gp_counters) ||
		(fixed && pmc >= pmu->nr_arch_fixed_counters);
}

int kvm_pmu_read_pmc(struct kvm_vcpu *vcpu, unsigned pmc, u64 *data)
{
	struct kvm_pmu *pmu = &vcpu->arch.pmu;
	bool fast_mode = pmc & (1u << 31);
	bool fixed = pmc & (1u << 30);
	struct kvm_pmc *counters;
	u64 ctr;

	pmc &= ~(3u << 30);
	if (!fixed && pmc >= pmu->nr_arch_gp_counters)
		return 1;
	if (fixed && pmc >= pmu->nr_arch_fixed_counters)
		return 1;
	counters = fixed ? pmu->fixed_counters : pmu->gp_counters;
	ctr = read_pmc(&counters[pmc]);
	if (fast_mode)
		ctr = (u32)ctr;
	*data = ctr;

	return 0;
}

void kvm_pmu_cpuid_update(struct kvm_vcpu *vcpu)
{
	struct kvm_pmu *pmu = &vcpu->arch.pmu;
	struct kvm_cpuid_entry2 *entry;
	union cpuid10_eax eax;
	union cpuid10_edx edx;

	pmu->nr_arch_gp_counters = 0;
	pmu->nr_arch_fixed_counters = 0;
	pmu->counter_bitmask[KVM_PMC_GP] = 0;
	pmu->counter_bitmask[KVM_PMC_FIXED] = 0;
	pmu->version = 0;
	pmu->reserved_bits = 0xffffffff00200000ull;
	pmu->freeze_perfmon_on_pmi = 0;
	pmu->freeze_lbrs_on_pmi = 0;
	pmu->debugctl_lbr = 0;

	entry = kvm_find_cpuid_entry(vcpu, 0xa, 0);
	if (unlikely(!entry)) {
		pmu->v_eax.full = 0;
		pmu->v_ebx.full = 0;
		pmu->v_edx.full = 0;
		return;
	}

	/* update virtual cpuid.eax 0xa */
	pmu->v_eax.full = entry->eax;
	pmu->v_ebx.full = entry->ebx;
	pmu->v_edx.full = entry->edx;

	eax.full = entry->eax;
	edx.full = entry->edx;

	pmu->version = eax.split.version_id;
	if (!pmu->version)
		return;

	pmu->nr_arch_gp_counters = min_t(int, eax.split.num_counters,
			INTEL_PMC_MAX_GENERIC);
	pmu->counter_bitmask[KVM_PMC_GP] = ((u64)1 << eax.split.bit_width) - 1;
	pmu->available_event_types = ~entry->ebx &
		((1ull << eax.split.mask_length) - 1);

	if (pmu->version == 1) {
		pmu->nr_arch_fixed_counters = 0;
	} else {
		pmu->nr_arch_fixed_counters =
			min_t(int, edx.split.num_counters_fixed,
					INTEL_PMC_MAX_FIXED);
		pmu->counter_bitmask[KVM_PMC_FIXED] =
			((u64)1 << edx.split.bit_width_fixed) - 1;
	}

	pmu->global_ctrl = ((1 << pmu->nr_arch_gp_counters) - 1) |
		(((1ull << pmu->nr_arch_fixed_counters) - 1) << INTEL_PMC_IDX_FIXED);
	pmu->global_ctrl_mask = ~pmu->global_ctrl;

	entry = kvm_find_cpuid_entry(vcpu, 7, 0);
	if (entry &&
			(boot_cpu_has(X86_FEATURE_HLE) || boot_cpu_has(X86_FEATURE_RTM)) &&
			(entry->ebx & (X86_FEATURE_HLE|X86_FEATURE_RTM)))
		pmu->reserved_bits ^= HSW_IN_TX|HSW_IN_TX_CHECKPOINTED;
}

void kvm_pmu_init(struct kvm_vcpu *vcpu)
{
	int i;
	struct kvm_pmu *pmu = &vcpu->arch.pmu;

	memset(pmu, 0, sizeof(*pmu));
	for (i = 0; i < INTEL_PMC_MAX_GENERIC; i++) {
		pmu->gp_counters[i].type = KVM_PMC_GP;
		pmu->gp_counters[i].vcpu = vcpu;
		pmu->gp_counters[i].idx = i;
		kvm_pmc_counter_set(&pmu->gp_counters[i], false);
	}
	for (i = 0; i < INTEL_PMC_MAX_FIXED; i++) {
		pmu->fixed_counters[i].type = KVM_PMC_FIXED;
		pmu->fixed_counters[i].vcpu = vcpu;
		pmu->fixed_counters[i].idx = i + INTEL_PMC_IDX_FIXED;
		kvm_pmc_counter_set(&pmu->fixed_counters[i], false);
	}
	init_irq_work(&pmu->irq_work, trigger_pmi);
	pmu->cap = kvm_pmu_get_real_pmu_capability();
	printk(KERN_NOTICE "cap->bit_width_fixed = %d\n", pmu->cap->bit_width_fixed);
	printk(KERN_NOTICE "cap->bit_width_gp = %d\n", pmu->cap->bit_width_gp);
	kvm_pmu_cpuid_update(vcpu);
}

void kvm_pmu_reset(struct kvm_vcpu *vcpu)
{
	struct kvm_pmu *pmu = &vcpu->arch.pmu;
	int i;

	irq_work_sync(&pmu->irq_work);
	for (i = 0; i < INTEL_PMC_MAX_GENERIC; i++) {
		struct kvm_pmc *pmc = &pmu->gp_counters[i];
		stop_counter(pmc);
		pmc->counter = pmc->eventsel = 0;
		kvm_pmc_counter_set(pmc, false);
	}

	for (i = 0; i < INTEL_PMC_MAX_FIXED; i++) {
		struct kvm_pmc *pmc = &pmu->fixed_counters[i];
		stop_counter(pmc);
		kvm_pmc_counter_set(pmc, false);
	}

	pmu->fixed_ctr_ctrl = pmu->global_ctrl = pmu->global_status =
		pmu->global_ovf_ctrl = 0;

	kvm_pmu_destroy_cap(&vcpu->arch.pmu);
	pmu->cap = kvm_pmu_get_real_pmu_capability();

	pmu->v_eax.full = pmu->v_ebx.full = pmu->v_edx.full = 0;
}

void kvm_pmu_destroy(struct kvm_vcpu *vcpu)
{
	kvm_pmu_reset(vcpu);
	kvm_pmu_destroy_cap(&vcpu->arch.pmu);
}

void kvm_handle_pmu_event(struct kvm_vcpu *vcpu)
{
	struct kvm_pmu *pmu = &vcpu->arch.pmu;
	u64 bitmask;
	int bit;

	bitmask = pmu->reprogram_pmi;
	printk(KERN_NOTICE "kvm_handle_pmu_event: pmu->reprogram_pmi = %llx\n", bitmask);
	kvm_pmu_freeze_perfmon_on_pmi(vcpu);
	kvm_pmu_freeze_lbrs_on_pmi(vcpu);

	for_each_set_bit(bit, (unsigned long *)&bitmask, X86_PMC_IDX_MAX) {
		struct kvm_pmc *pmc = global_idx_to_pmc(pmu, bit);

		if (unlikely(!pmc || !pmc->perf_event)) {
			clear_bit(bit, (unsigned long *)&pmu->reprogram_pmi);
			continue;
		}

		reprogram_idx(pmu, bit);
	}
}

void kvm_deliver_pmi(struct kvm_vcpu *vcpu)
{
	printk(KERN_NOTICE "kvm_deliver_pmi\n");
	if (vcpu->arch.apic)
		kvm_apic_local_deliver_nmi(vcpu->arch.apic, APIC_LVTPC);
}

u64 kvm_pmu_read_debugctl_msr(struct kvm_vcpu *vcpu)
{
	u64 data = 0;
	struct kvm_pmu *pmu = &vcpu->arch.pmu;
	if (pmu->freeze_perfmon_on_pmi) {
		data |= DEBUGCTLMSR_FREEZE_PERFMON_ON_PMI;
	}
	if (pmu->freeze_lbrs_on_pmi) {
		data |= DEBUGCTLMSR_FREEZE_LBRS_ON_PMI;
	}
	if (pmu->debugctl_lbr) {
		data |= DEBUGCTLMSR_LBR;
	}
	printk(KERN_NOTICE "pmu.c, kvm_pmu_read_debugctl_msr: %llx\n", data);
	return data;
}

void kvm_pmu_write_debugctl_msr(struct kvm_vcpu *vcpu, u64 data)
{
	struct kvm_pmu *pmu = &vcpu->arch.pmu;
	if (data & DEBUGCTLMSR_FREEZE_PERFMON_ON_PMI) {
		printk(KERN_NOTICE "pmu.c, set pmu.freeze_perfmon_on_pmi\n");
		pmu->freeze_perfmon_on_pmi = 1;
	}
	else {
		printk(KERN_NOTICE "pmu.c, clear pmu.freeze_perfmon_on_pmi\n");
		pmu->freeze_perfmon_on_pmi = 0;
	}
	if (data & DEBUGCTLMSR_FREEZE_LBRS_ON_PMI) {
		printk(KERN_NOTICE "pmu.c, set pmu.freeze_lbrs_on_pmi\n");
		pmu->freeze_lbrs_on_pmi = 1;
	}
	else {
		printk(KERN_NOTICE "pmu.c, clear pmu.freeze_lbrs_on_pmi\n");
		pmu->freeze_lbrs_on_pmi = 0;
	}
	if (data & DEBUGCTLMSR_LBR) {
		printk(KERN_NOTICE "pmu.c, set debugctrl lbr\n");
		pmu->debugctl_lbr = 1;
		kvm_pmu_set_debugctl_lbr(vcpu, true);
	}
	else {
		printk(KERN_NOTICE "pmu.c, clear debugctrl lbr\n");
		pmu->debugctl_lbr = 0;
		kvm_pmu_set_debugctl_lbr(vcpu, false);
	}
}
