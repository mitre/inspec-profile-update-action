control 'SV-23721' do
  title 'The Fire and Emergency Services (FES) communications over a sites private telephone system must route emergency calls as a priority call in a non-blocking manner.'
  desc 'When calling the designated F&ES telephone number, the call must go through regardless of the state of other calls in the system. As such, emergency calls must be treated as a priority call by the system. 

For enterprise systems, the support for E911 by the Enterprise LSC (or any remote LSC construct) is governed by FCC rules, as well as other federal, state, and local law. The design and implementation of all telephone systems must include reasonable efforts to provide E911, even when the access connection to the Enterprise LSC is severed.'
  desc 'check', 'Interview the ISSO to validate compliance with the following requirement: 
Inspect the telephone system configuration and routing tables to determine compliance with the requirement. Verify the local DoD telephone system, VoIP or traditional, routes calls to the designated local emergency services number at the public and private emergency services answering point (PSAP) as a priority call in a non-blocking manner. 

If an emergency services number is not designated to access an emergency services answering point or call center whether internal to the local site or to another local agency or municipality, this is a finding.

If calls to this number are not treated as a priority call in a non-blocking manner, this is a finding.

NOTE: In the event the F&ES calls are routed to a public entity outside the private telephone system, the call must route to an internal emergency number in parallel with the external call. Both calls should have the same priority. This is so that the site can be aware of the emergency and assist the F&ES responders in reaching the location of the caller. F&ES calls may be routed to an internal on-site F&ES answering point providing the site maintains robust local police, fire, and medical services such that these can replace public services. In the event a public F&ES answering point is the primary answering point for the site, calls must be directly routed to it and not relayed via a local emergency answering point. A second call from the local emergency answering point should not be required to obtain emergency services from the public F&ES answering point unless the site maintains full and comparable police, fire, and medical services and its answering point is the primary. In the event a local private answering point is the primary answering point, and if this private answering point is not fully staffed on a 24-7 basis, the telephone system must route F&ES calls to the public answering point when the local answering point is not fully staffed, for example outside the normal working hours of the site.'
  desc 'fix', 'Configure the local DoD telephone system, VoIP or traditional, to routes calls to the designated local emergency services number at the public or private emergency services answering point (PSAP) as a priority call in a non-blocking manner. Configure the telephone system to treat calls to the designated emergency services number as a priority call in a non-blocking manner.'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-25754r3_chk'
  tag severity: 'medium'
  tag gid: 'V-21512'
  tag rid: 'SV-23721r3_rule'
  tag stig_id: 'VVT 2005'
  tag gtitle: 'VVT 2005'
  tag fix_id: 'F-22300r3_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'Information Assurance Manager']
end
