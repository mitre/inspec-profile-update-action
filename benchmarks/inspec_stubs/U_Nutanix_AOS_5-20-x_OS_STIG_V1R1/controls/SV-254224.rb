control 'SV-254224' do
  title 'Nutanix AOS must enable FIPS mode to implement NIST FIPS-validated cryptography.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The operating system must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

'
  desc 'check', 'Confirm Nutanix AOS implements DoD-approved encryption to protect the confidentiality of remote access sessions.

Determine if the "dracut-fips" package is installed with the following command:

$ sudo yum list installed dracut-fips
dracut-fips.x86_64-033-572.el7 

If dracut-fips package is not installed, this is a finding.

Determine if FIPS mode is enabled with the following command:

$ fipscheck
usage: fipscheck [-s <hmac-suffix>] <paths-to-files>
fips mode is on

If FIPS mode is "on", Determine if the kernel boot parameter is configured for FIPS mode with the following command:

$ sudo cat /boot/grub/grub.conf | grep fips

It the  kernel output does not list "fips=1", this is a finding.

If the kernel boot parameter is configured to use FIPS mode, Determine if the system is in FIPS mode with the following command:

$ sudo cat /proc/sys/crypto/fips_enabled
1

If FIPS mode is not "on", the kernel boot parameter is not configured for FIPS mode, or the system does not have a value of "1" for "fips_enabled" in "/proc/sys/crypto", this is a finding.'
  desc 'fix', 'Configure the system to run in FIPS mode by running the following command:

$ sudo salt-call state.sls security/CVM/fipsCVM'
  impact 0.7
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57709r846758_chk'
  tag severity: 'high'
  tag gid: 'V-254224'
  tag rid: 'SV-254224r846760_rule'
  tag stig_id: 'NUTX-OS-001460'
  tag gtitle: 'SRG-OS-000478-GPOS-00223'
  tag fix_id: 'F-57660r846759_fix'
  tag satisfies: ['SRG-OS-000478-GPOS-00223', 'SRG-OS-000396-GPOS-00176']
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
