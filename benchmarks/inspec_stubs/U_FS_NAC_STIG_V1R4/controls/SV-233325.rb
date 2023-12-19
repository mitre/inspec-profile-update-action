control 'SV-233325' do
  title 'Forescout must generate a critical alert to be sent to the Information System Security Officer (ISSO) and Systems Administrator (SA) (at a minimum) in the event of an audit processing failure. This is required for compliance with C2C Step 1.'
  desc 'Ensuring that a security solution alerts in the event of misconfiguration or error is imperative to ensuring that proper auditing is being conducted. Having the ability to immediately notify an administrator when this auditing fails allows for a quick response and real-time remediation.'
  desc 'check', 'If DoD is not at C2C Step 1 or higher, this is not a finding.

Verify Forescout sends an alert to the proper security personnel when an audit process failure occurs. 

1. Log on to the Forescout UI.
2. Locate the audit process policies as identified by the site representative.
3. Verify a policy for "audit failure" exists.
4. Verify this policy includes notification of security personnel.

If Forescout does not send an alert when an audit processing failure occurs, this is a finding.'
  desc 'fix', 'Log on to the Forescout UI.

1. Locate the audit process policies as identified by the site representative.
2. Configure a policy for audit failure to include the notification of security personnel. This could also include sending a balloon message, notification, or email.'
  impact 0.5
  ref 'DPMS Target Forescout Network Access Control'
  tag check_id: 'C-36520r811398_chk'
  tag severity: 'medium'
  tag gid: 'V-233325'
  tag rid: 'SV-233325r856511_rule'
  tag stig_id: 'FORE-NC-000170'
  tag gtitle: 'SRG-NET-000335-NAC-001360'
  tag fix_id: 'F-36485r605679_fix'
  tag 'documentable'
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']
end
