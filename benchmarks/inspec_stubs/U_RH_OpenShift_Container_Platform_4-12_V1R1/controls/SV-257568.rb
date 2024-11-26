control 'SV-257568' do
  title 'Red Hat Enterprise Linux CoreOS (RHCOS) must implement nonexecutable data to protect its memory from unauthorized code execution.'
  desc 'The NX bit is a hardware feature that prevents the execution of code from data memory regions. By enabling NX bit execute protection, OpenShift ensures that malicious code or exploits cannot execute from areas of memory that are intended for data storage. This helps protect against various types of buffer overflow attacks, where an attacker attempts to inject and execute malicious code in data memory.'
  desc 'check', %q(Verify the NX (no-execution) bit flag is set on the system by executing the following:

for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'echo -n "$HOSTNAME "; dmesg | grep Execute ' 2>/dev/null; done

Example Output:([ 0.000000] NX (Execute Disable) protection: active)

If "dmesg" does not show "NX (Execute Disable) protection active", check the cpuinfo settings by executing the following command: 

for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'echo -n "$HOSTNAME "; less /proc/cpuinfo | grep 'nx' /proc/cpuinfo | uniq' 2>/dev/null; done

(Example Output: flags : fpu vme de pse tsc ms nx rdtscp lm constant_tsc...)

If "flags" does not contain the "nx" flag, this is a finding.)
  desc 'fix', 'The NX bit execute protection must be enabled in the system BIOS. The nodes must be reinstalled. Follow the steps found here for more information:
https://access.redhat.com/solutions/2936741'
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61303r921645_chk'
  tag severity: 'medium'
  tag gid: 'V-257568'
  tag rid: 'SV-257568r921647_rule'
  tag stig_id: 'CNTR-OS-000860'
  tag gtitle: 'SRG-APP-000450-CTR-001105'
  tag fix_id: 'F-61227r921646_fix'
  tag 'documentable'
  tag cci: ['CCI-002824']
  tag nist: ['SI-16']
end
