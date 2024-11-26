control 'SV-256523' do
  title 'The Photon operating system must protect audit tools from unauthorized modification and deletion.'
  desc 'Protecting audit information includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operations on audit information.

'
  desc 'check', 'At the command line, run the following command:

# stat -c "%n is owned by %U and group owned by %G and permissions are %a" /usr/sbin/auditctl /usr/sbin/auditd /usr/sbin/aureport /usr/sbin/ausearch /usr/sbin/autrace

If any file is not owned by root or group-owned by root or permissions are more permissive than "750", this is a finding.'
  desc 'fix', 'At the command line, run the following command for each file returned for user and group ownership:

# chown root:root <file>

At the command line, run the following command for each file returned for file permissions:

# chmod 750 <file>'
  impact 0.5
  ref 'DPMS Target VMware vSphere 7.0 vCA Photon OS'
  tag check_id: 'C-60198r887241_chk'
  tag severity: 'medium'
  tag gid: 'V-256523'
  tag rid: 'SV-256523r887243_rule'
  tag stig_id: 'PHTN-30-000048'
  tag gtitle: 'SRG-OS-000257-GPOS-00098'
  tag fix_id: 'F-60141r887242_fix'
  tag satisfies: ['SRG-OS-000257-GPOS-00098', 'SRG-OS-000258-GPOS-00099']
  tag 'documentable'
  tag cci: ['CCI-001494', 'CCI-001495']
  tag nist: ['AU-9', 'AU-9']
end
