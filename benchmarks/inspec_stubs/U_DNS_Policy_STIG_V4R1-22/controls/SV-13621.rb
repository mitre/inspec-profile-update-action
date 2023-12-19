control 'SV-13621' do
  title 'The contents of zones are not reviewed at least annually.'
  desc 'DNS administrators must review the contents of their zones at least as often as annually for content or aggregation of content that may provide an adversary information that can potentially compromise operational security. This specifically includes names that provide an outsider some indication as to the function of the referenced system unless the function is obvious in the context of other standard DNS information (e.g., naming a DNS server as dns.zone.mil or an SMTP mail server as mail.zone.mil is not an OPSEC violation given that the functions of these servers are easily identifiable during DNS queries). The DNS administrator is the final adjudicator of the sensitivity of DNS information, in concert with the OPSEC processes of the organization, but should make a conscious decision to include such information based on operational need. NIST guidance includes specific guidelines that HINFO, RP and LOC records not be included in the zone.'
  desc 'check', 'Interview the DNS administrator and ask if there is a procedure in place to review and validate the contents of the zones he/she is responsible for, at least annually.'
  desc 'fix', 'The IAO will ensure the DNS administrator reviews the contents of the zones they are responsible for, at least annually.'
  impact 0.3
  ref 'DPMS Target DNS Policy'
  tag check_id: 'C-9298r1_chk'
  tag severity: 'low'
  tag gid: 'V-13053'
  tag rid: 'SV-13621r1_rule'
  tag stig_id: 'DNS0185'
  tag gtitle: 'Contents of zones are not reviewed.'
  tag fix_id: 'F-12295r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
