control 'SV-6996' do
  title 'There is no section within the SFUG, or equivalent documentation, describing the correct usage and handling of USB technologies.'
  desc 'The Security Features User Guide gives the user a single reference for information on the current general and site policies and procedures describing their security responsibilities.  The lack of this reference could lead to the compromise of sensitive data.
The reviewer will interview the IAO and review the relevant document.  What needs to be here is a description for handling, and labeling of USB devices.  Additionally an explanation of the restrictions placed on attaching non-government owned USB devices to a government owned IS and the prohibition of disguised USB jump drives.'
  desc 'check', 'The reviewer will interview the IAO and review the relevant document.  What needs to be here is a description for handling, and labeling of USB devices.  Additionally an explanation of the restrictions placed on attaching non-government owned USB devices to a government owned IS and the prohibition of disguised USB jump drives.'
  desc 'fix', 'Develop, update, and distribute a SFUG section dealing with USB devices in accordance with the SPAN STIG.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-2936r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6774'
  tag rid: 'SV-6996r1_rule'
  tag stig_id: 'USB01.009.00'
  tag gtitle: 'USB SFUG Section'
  tag fix_id: 'F-6427r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
  tag ia_controls: 'PRRB-1'
end
