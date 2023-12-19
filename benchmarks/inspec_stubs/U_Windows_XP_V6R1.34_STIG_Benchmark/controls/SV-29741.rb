control 'SV-29741' do
  title 'Auditing records are configured as required.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, analyze compromises that have occurred as well as detect an attack that has begun or is about to begin. Audit logs are necessary to provide a trail of evidence in case the system or network is compromised.  Without an audit trail that provides information as to event that occurred and if it was successful or unsuccessful, it is difficult to analyze a series of events to determine the steps used by an attacker to compromise a system or network, or what exactly happened that led to a denial of service. Collecting data such as the successful and unsuccessful events is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected behavior.'
  desc 'fix', 'Configure the system to audit categories as outlined in check procedure.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag severity: 'medium'
  tag gid: 'V-6850'
  tag rid: 'SV-29741r1_rule'
  tag gtitle: 'Auditing Configuration'
  tag fix_id: 'F-6539r1_fix'
  tag 'documentable'
  tag potential_impacts: 'none'
  tag third_party_tools: ['HK', 'HK']
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'ECAR-3, ECAR-2'
end
