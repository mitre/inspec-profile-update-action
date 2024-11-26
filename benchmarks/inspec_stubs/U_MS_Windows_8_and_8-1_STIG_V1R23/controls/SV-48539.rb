control 'SV-48539' do
  title 'Unauthorized accounts must not have the Load and unload device drivers user right.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

The "Load and unload device drivers" user right allows device drivers to dynamically be loaded on a system by a user. This could potentially be used to install malicious code by an attacker.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.) 
Expand the Security Configuration and Analysis tree view. 
Navigate to Local Policies -> User Rights Assignment.

If any accounts or groups other than the following are granted the "Load and unload device drivers" user right, this is a finding:

Administrators'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Load and unload device drivers" to only include the following accounts or groups:

Administrators'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45189r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26493'
  tag rid: 'SV-48539r2_rule'
  tag stig_id: 'WN08-UR-000028'
  tag gtitle: 'Load and unload device drivers'
  tag fix_id: 'F-41661r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
