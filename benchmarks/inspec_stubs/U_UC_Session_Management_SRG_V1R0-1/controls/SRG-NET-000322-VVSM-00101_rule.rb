control 'SRG-NET-000322-VVSM-00101_rule' do
  title 'The Unified Communications Session Manager must be configured to enforce changes to privileges of Voice Video Endpoint device access.'
  desc 'Without the enforcement of immediate change to privilege levels, users and devices may not provide the correct level of service. Privileges include access to outside connections, precedence, and preemption capabilities. A user with higher precedence and preemption capability may supplant users authorized higher levels of access. Endpoints must be limited to the privileges needed to conduct business and changes to privileges must be enforced immediately.

Access authorizations should be dynamic to reflect changing conditions; if a revocation is not enforced in a timely manner, users may have inappropriate access. Revocation of access rules may differ based on the types of access revoked. For example, if a subject (i.e., user or process) is removed from a group, access may not be revoked until the next time the object (e.g., file) is opened or until the next time the subject attempts a new access to the object. Revocation based on changes to security labels may take effect immediately. It may be necessary to immediately revoke access in certain circumstances (i.e., a compromised account is being used). 

This may be mitigated by implementing SRG-NET-000321-VVSM-00007.'
  desc 'check', 'Verify the Unified Communications Session Manager enforces change to privileges of Voice Video Endpoint device access. Privileges include access to outside connections, precedence, and preemption capabilities.

If the Unified Communications Session Manager does not enforce changes to privileges of Voice Video Endpoint device access, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Session Manager to enforce changes to privileges of Voice Video Endpoint device access.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000322-VVSM-00101_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000322-VVSM-00101'
  tag rid: 'SRG-NET-000322-VVSM-00101_rule'
  tag stig_id: 'SRG-NET-000322-VVSM-00101'
  tag gtitle: 'SRG-NET-000322-VVSM-00101'
  tag fix_id: 'F-SRG-NET-000322-VVSM-00101_fix'
  tag 'documentable'
  tag cci: ['CCI-002179']
  tag nist: ['AC-3 (8)']
end
