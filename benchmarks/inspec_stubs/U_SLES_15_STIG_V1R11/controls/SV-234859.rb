control 'SV-234859' do
  title 'FIPS 140-2 mode must be enabled on the SUSE operating system.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of using encryption to protect data. The SUSE operating system must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

'
  desc 'check', 'Verify the SUSE operating system is running in FIPS mode by running the following command.

> cat /proc/sys/crypto/fips_enabled 

1

If nothing is returned, the file does not exist, or the value returned is "0", this is a finding.'
  desc 'fix', 'To configure the SUSE operating system to run in FIPS mode, add "fips=1" to the kernel parameter during the SUSE operating system install.

Enabling FIPS mode on a preexisting system involves a number of modifications to the SUSE operating system. Refer to section 9.1, "Crypto Officer Guidance", of the following document for installation guidance:

http://csrc.nist.gov/groups/STM/cmvp/documents/140-1/140sp/140sp2435.pdf'
  impact 0.7
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38047r618846_chk'
  tag severity: 'high'
  tag gid: 'V-234859'
  tag rid: 'SV-234859r877380_rule'
  tag stig_id: 'SLES-15-010510'
  tag gtitle: 'SRG-OS-000396-GPOS-00176'
  tag fix_id: 'F-38010r618847_fix'
  tag satisfies: ['SRG-OS-000396-GPOS-00176', 'SRG-OS-000478-GPOS-00223']
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
