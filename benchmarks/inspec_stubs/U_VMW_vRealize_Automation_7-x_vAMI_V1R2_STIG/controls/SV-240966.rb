control 'SV-240966' do
  title 'The vAMI must be configured to listen on a specific IPv4 address.'
  desc 'Configuring the application to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements. Configuration settings are the set of parameters that can be changed that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the application, including the parameters required to satisfy other security control requirements.'
  desc 'check', 'At the command prompt, execute the following command:

grep ip4AddrList /opt/vmware/etc/sfcb/sfcb.cfg

If the value of "ip4AddrList" is missing, commented out, or not set, this is a finding.'
  desc 'fix', "Navigate to and open /opt/vmware/etc/sfcb/sfcb.cfg,

Configure the sfcb.cfg file with the following value: 'ip4AddrList: <ip v4 address>'

Note: Replace <ip v4 address> with the appropriate site-specific IPv4 address."
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x vAMI'
  tag check_id: 'C-44199r676063_chk'
  tag severity: 'medium'
  tag gid: 'V-240966'
  tag rid: 'SV-240966r879887_rule'
  tag stig_id: 'VRAU-VA-000650'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-44158r676064_fix'
  tag 'documentable'
  tag legacy: ['SV-100927', 'V-90277']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
