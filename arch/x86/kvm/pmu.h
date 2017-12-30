#ifndef __KVM_X86_PMU_H
#define __KVM_X86_PMU_H
#include <asm/asm.h>
#include <asm/vmx.h>
#include <linux/kvm_host.h>
#include <linux/types.h>

#define __pmu_ex_clear(x, reg) \
	____kvm_handle_fault_on_reboot(x, "xor " reg ", " reg)

#define __pmu_ex(x) __kvm_handle_fault_on_reboot(x)

void kvm_deliver_pmi(struct kvm_vcpu *vcpu);
bool kvm_pmu_msr(struct kvm_vcpu *vcpu, u32 msr);
int kvm_pmu_get_msr(struct kvm_vcpu *vcpu, u32 index, u64 *data);
int kvm_pmu_set_msr(struct kvm_vcpu *vcpu, struct msr_data *msr_info);
int kvm_pmu_check_pmc(struct kvm_vcpu *vcpu, unsigned pmc);
int kvm_pmu_read_pmc(struct kvm_vcpu *vcpu, unsigned pmc, u64 *data);
void kvm_pmu_cpuid_update(struct kvm_vcpu *vcpu);
void kvm_pmu_init(struct kvm_vcpu *vcpu);
void kvm_pmu_reset(struct kvm_vcpu *vcpu);
void kvm_pmu_destroy(struct kvm_vcpu *vcpu);
void kvm_handle_pmu_event(struct kvm_vcpu *vcpu);
void kvm_pmu_set_debugctl_lbr(struct kvm_vcpu *vcpu, bool flag);
u64 kvm_pmu_read_debugctl_msr(struct kvm_vcpu *vcpu);

#endif /* __KVM_X86_PMU_H */
