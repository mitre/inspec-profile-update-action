control 'SV-45386' do
  title 'The IDPS must produce audit records containing information to establish the outcome of events associated with detected harmful or potentially harmful traffic, including, at a minimum, capturing all associated communications traffic.'
  desc 'Associating event outcome with detected events in the log provides a means of investigating an attack or suspected attack.

While auditing and logging are closely related, they are not the same. Logging is recording data about events that take place in a system, while auditing is the use of log records to identify security-relevant information such as system or user accesses. In short, log records are audited to establish an accurate history. Without logging, it would be impossible to establish an audit trail.

The logs should identify what servers, destination addresses, applications, or databases were potentially attacked by logging communications traffic between the target and the attacker. All commands that were entered by the attacker (such as account creations, changes in permissions, files accessed, etc.) during the session should also be logged.'
  desc 'check', 'Verify the entries sent to the audit log include, at a minimum, capturing all associated communications traffic.

If the audit log event records do not include, at a minimum, capturing all associated communications traffic, this is a finding.'
  desc 'fix', 'Configure the IDPS components to ensure entries sent to the audit log include, at a minimum, capturing all associated communications traffic.'
  impact 0.5
  ref 'DPMS Target SRG-NET-IDPS'
  tag check_id: 'C-42735r5_chk'
  tag severity: 'medium'
  tag gid: 'V-34544'
  tag rid: 'SV-45386r2_rule'
  tag stig_id: 'SRG-NET-000078-IDPS-00063'
  tag gtitle: 'SRG-NET-000078-IDPS-00063'
  tag fix_id: 'F-38783r5_fix'
  tag 'documentable'
  tag cci: ['CCI-000134']
  tag nist: ['AU-3 e']
end
