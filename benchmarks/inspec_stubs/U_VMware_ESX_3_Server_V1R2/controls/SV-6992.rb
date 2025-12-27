control 'SV-6992' do
  title 'Persistent memory USB devices are not treated as removable media and contrary to DODD 5200.1-R; the devices are not secured, transported, and sanitized in a manner appropriate for the classification level of the data they contain.'
  desc 'Persistent memory USB devices can function as removable media.  They have the same vulnerabilities as floppy disk but greater capacity.  They will be secured, transported and sanitized as required by DODD 5200-1-R in a manner appropriate for the classification level of the data they contain.
The IAO, SA, and user will ensure that persistent memory USB devices are treated as removable media and, in accordance with DODD 5200.1-R; the devices are secured, transported, and sanitized in a manner appropriate for the classification level of the data they contain.'
  desc 'check', 'The reviewer will interview the IAO to verify that the policy for treating persistent memory USB devices as removable media, and in accordance with DODD 5200.1-R; the devices are secured, transported, and sanitized in a manner appropriate for the classification level of the data they contain is disseminated to all users.  This would include any device with internal non-removable persistent memory not just jump drives or disk driver.'
  desc 'fix', 'Disseminate the policy requiring that persistent memory USB devices will be treated as removable media and, in accordance with DODD 5200.1-R; the devices will be secured, transported, and sanitized in a manner appropriate for the classification level of the data they contain.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-2920r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6770'
  tag rid: 'SV-6992r1_rule'
  tag stig_id: 'USB01.005.00'
  tag gtitle: 'USB Persistent Memory DODD 5200-1-R Treatment'
  tag fix_id: 'F-6423r1_fix'
  tag 'documentable'
  tag responsibility: ['Other', 'Information Assurance Officer', 'System Administrator']
  tag ia_controls: 'PECS-1, PECS-2, PEDD-1'
end
