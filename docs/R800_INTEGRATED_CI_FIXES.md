# Integrated CI fixes (NON-RELEASE)

On 5f1a8b9, run 45541179243 compiled ARM64 Image and ABOX; effective
config had PCM/COMPAT/ABOX enabled. Post-build gate incorrectly required
a composite snd-pcm.o, rather than the individual built-in objects.
On a98281fdfbf91ebc57e4f8adb5e8f95a27061a05, run 45544782743 had 584 tests, 7 skipped because DTC tools
were missing; strict regression correctly failed. Run 45544782614
failed in generic ARM64 smp.c because Samsung debug-snapshot function
is declared only with CONFIG_DEBUG_SNAPSHOT. Guard the call at compile
time, keeping Samsung-config behavior unchanged. Install DTC tools
before regression and check individual PCM objects. No relaxation of
skip gate or hardware/boot criteria. New exact-head CI not yet verified.
safe_to_flash=false.
