control 'SRG-NET-000088-VVSM-00101_rule' do
  title 'The Unified Communications Session Manager must alert the information system security officer (ISSO) and system administrator(SA) (at a minimum) in the event of a session (call) record system failure.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process session records. Without this notification, the security personnel may be unaware of an impending failure of the session record capability. Session record processing failures include software/hardware errors, failures in the capturing mechanisms, and storage capacity being reached or exceeded.

This requirement applies to each session record data storage repository (i.e., distinct information system component where session records are stored), the centralized session record storage capacity of organizations (i.e., all session record data storage repositories combined), or both.'
  desc 'check', 'Verify the Unified Communications Session Manager alerts the ISSO and SA (at a minimum) in the event of a session record system failure.

If the Unified Communications Session Manager does not alert the ISSO and SA (at a minimum) in the event of a session record system failure, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Session Manager to alert the ISSO and SA (at a minimum) in the event of a session record system failure.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000088-VVSM-00101_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000088-VVSM-00101'
  tag rid: 'SRG-NET-000088-VVSM-00101_rule'
  tag stig_id: 'SRG-NET-000088-VVSM-00101'
  tag gtitle: 'SRG-NET-000088-VVSM-00101'
  tag fix_id: 'F-SRG-NET-000088-VVSM-00101_fix'
  tag 'documentable'
  tag cci: ['CCI-000139']
  tag nist: ['AU-5 a']
end
