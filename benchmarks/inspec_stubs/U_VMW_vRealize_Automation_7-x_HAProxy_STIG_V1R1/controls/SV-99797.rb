control 'SV-99797' do
  title 'HAProxy log files must be backed up onto a different system or media.'
  desc 'Log data is essential in the investigation of events. If log data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity would be difficult, if not impossible, to achieve. In addition, access to log records provides information an attacker could potentially use to their advantage since each event record might contain communication ports, protocols, services, trust relationships, user names, etc.'
  desc 'check', 'Interview the ISSO.

Determine whether log data and records are being backed up to a different system or separate media.

If log data and records are not being backed up to a different system or separate media, this is a finding.'
  desc 'fix', 'Ensure log data and records are being backed up to a different system or separate media.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x HAProxy'
  tag check_id: 'C-88839r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89147'
  tag rid: 'SV-99797r1_rule'
  tag stig_id: 'VRAU-HA-000110'
  tag gtitle: 'SRG-APP-000125-WSR-000071'
  tag fix_id: 'F-95889r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001348']
  tag nist: ['AU-9 (2)']
end
