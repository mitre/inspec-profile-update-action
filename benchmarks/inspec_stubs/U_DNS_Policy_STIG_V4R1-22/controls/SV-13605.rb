control 'SV-13605' do
  title 'A patch and DNS software upgrade log; to include the identity of the administrator, date and time each patch or upgrade was implemented,  is not maintained.'
  desc 'DNS software has a history of vulnerabilities and new ones may be discovered at any time.  To ensure that attackers cannot take advantage of known DNS vulnerabilities applicable software patches and patches must be applied.  Patch and DNS software upgrade documentation must be maintained to ensure the DNS name servers are protected from these vulnerabilities and current with required patches and software upgrades.'
  desc 'check', 'DNS patch and upgrade change records must include records of the date and time each patch or upgrade to DNS software was implemented, and by whom.  The method of verification may be considered weak, but the requirement is merely to document the dates and times of DNS software patch and upgrades.

Instruction:  If there is no patch and upgrade log, then this is a finding.  If there is such a log, then entries must include the date and time of any change as well as the identity of the administrator.  Failure to include this information for any entry is a finding.'
  desc 'fix', 'The SA should establish and maintain a log of the date and time each patch and upgrade to DNS software was implemented.'
  impact 0.3
  ref 'DPMS Target DNS Policy'
  tag check_id: 'C-3360r1_chk'
  tag severity: 'low'
  tag gid: 'V-13037'
  tag rid: 'SV-13605r1_rule'
  tag stig_id: 'DNS0130'
  tag gtitle: 'DNS patch/software log is not maintained.'
  tag fix_id: 'F-4342r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
