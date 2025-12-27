control 'SV-76933' do
  title 'ColdFusion must have the Default ScriptSrc Directory set to a non-default value.'
  desc 'The scripts directory contains common javascript code that may be used by the hosted applications.  This code is offered to help the developer with common data controls and functions aiding in the quick development of applications.  Unfortunately, this code has also been known to have security vulnerabilities.  Because of this, many of the ColdFusion hacking tools look for this directory in the default location searching for files with known vulnerabilities.  By moving the directory to a non-default location, the hacking tools are unable to find the directory making it more difficult for the attacker.'
  desc 'check', 'Within the Administrator Console, navigate to the "Settings" page under the "Server Settings" menu.

If the "Default ScriptSrc Directory" is set to /CFIDE/scripts/", this is a finding.'
  desc 'fix', 'Navigate to the "Settings" page under the "Server Settings" menu.  Enter the new location for the ScriptSrc Directory.'
  impact 0.5
  ref 'DPMS Target ColdFusion 11'
  tag check_id: 'C-63247r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62443'
  tag rid: 'SV-76933r1_rule'
  tag stig_id: 'CF11-03-000116'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-68363r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
