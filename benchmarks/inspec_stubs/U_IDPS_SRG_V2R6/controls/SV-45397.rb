control 'SV-45397' do
  title 'In the event of a logging failure caused by the lack of audit record storage capacity, the IDPS must continue generating and storing audit records if possible, overwriting the oldest audit records in a first-in-first-out manner.'
  desc 'It is critical that when the IDPS is at risk of failing to process audit logs as required, it takes action to mitigate the failure.

The IDPS performs a critical security function, so its continued operation is imperative. Since availability of the IDPS is an overriding concern, shutting down the system in the event of an audit failure should be avoided, except as a last resort.'
  desc 'check', 'Verify the IDPS, in the event of a logging failure caused by the lack of audit record storage capacity, continues generating and storing audit records and overwriting the oldest audit records in a first-in-first-out manner.

In the event of a logging failure caused by the lack of audit record storage capacity, if the IDPS does not continue generating and storing audit records and overwriting the oldest audit records in a first-in-first-out manner, this is a finding.'
  desc 'fix', 'Configure the IDPS to, in the event of a logging failure caused by the lack of audit record storage capacity, continue generating and storing audit records and overwriting the oldest audit records in a first-in-first-out manner.'
  impact 0.5
  ref 'DPMS Target SRG-NET-IDPS'
  tag check_id: 'C-42746r2_chk'
  tag severity: 'medium'
  tag gid: 'V-34555'
  tag rid: 'SV-45397r2_rule'
  tag stig_id: 'SRG-NET-000089-IDPS-00069'
  tag gtitle: 'SRG-NET-000089-IDPS-00069'
  tag fix_id: 'F-38794r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']
end
