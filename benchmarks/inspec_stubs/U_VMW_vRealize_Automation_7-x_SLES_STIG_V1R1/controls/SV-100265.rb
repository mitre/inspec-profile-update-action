control 'SV-100265' do
  title 'The tftp package must not be installed.'
  desc 'The Trivial File Transfer Protocol (TFTP) is normally used only for booting diskless workstations and for getting or saving network component configuration files. Disabling the "tftp" protocol service ensures the system is not acting over tftp, which does not provide encryption or authentication.'
  desc 'check', 'Check if "tftp" is installed:

# rpm -q tftp

If there is a "tftp" package listed, this is a finding.'
  desc 'fix', 'To remove the "tftp" package use the following command:

rpm -e tftp'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x SLES'
  tag check_id: 'C-89307r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89615'
  tag rid: 'SV-100265r1_rule'
  tag stig_id: 'VRAU-SL-000490'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-96357r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
