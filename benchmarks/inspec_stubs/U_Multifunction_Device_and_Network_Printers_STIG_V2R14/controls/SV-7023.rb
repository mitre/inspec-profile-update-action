control 'SV-7023' do
  title 'Implementation of an MFD and printer security policy for the protection of classified information.'
  desc 'Department of Defense Manual 5200.01, "Protection of Classified Information" provides policy, assigns responsibilities, and provides procedures for the designation, marking, protection, and dissemination of controlled unclassified information (CUI) and classified information.  DoDM 5200.01, Volume 3, Section 14 mandates that organizations identify equipment used for classified processing and develop security procedures to safeguard these devices.  

This requires that each organization have an MFD and printer security policy that lists the following safeguards: 
a. Prevent unauthorized access to that information, including by repair or maintenance personnel.
b. Ensure that repair procedures do not result in unauthorized dissemination of or access to classified information.
c. Replace and destroy equipment parts in the appropriate manner when classified information cannot be removed.
d. Ensure that appropriately knowledgeable, cleared personnel inspect equipment and associated media used to process classified information before the equipment is removed from protected areas to ensure there is no retained classified information.
e. Ensure MFD and printers used to process classified information are certified and accredited in accordance with DoDD 8500.01E. 
f. Ensure that MFD and printers address issues concerning compromising emanations in accordance with DoDD 8500.01E.'
  desc 'check', "Obtain and review the organization's MFD and printer security policy.  If none is provided, this is a finding.  If it does not prescribe the appropriate safeguards listed below, this is a finding.
Safeguards to be listed in the organization's MFD and printer security policy;
a. Prevent unauthorized access to that information, including by repair or maintenance personnel.
b. Ensure that repair procedures do not result in unauthorized dissemination of or access to classified information.
c. Replace and destroy equipment parts in the appropriate manner when classified information cannot be removed.
d. Ensure that appropriately knowledgeable, cleared personnel inspect equipment and associated media used to process classified information before the equipment is removed from protected areas to ensure there is no retained classified information.
e. Ensure MFD and printers used to process classified information are certified and accredited in accordance with DoDD 8500.01E. 
f. Ensure that MFD and printers address issues concerning compromising emanations in accordance with DoDD 8500.01E."
  desc 'fix', 'Develop and implement an MFD and printer security policy consistent with DoDM 5200.01, Volume 3, Section 14.'
  impact 0.3
  ref 'DPMS Target Multifunction Device - MFD'
  tag check_id: 'C-3006r3_chk'
  tag severity: 'low'
  tag gid: 'V-6798'
  tag rid: 'SV-7023r3_rule'
  tag stig_id: 'MFD06.002'
  tag gtitle: 'MFD/Printer Security Policy'
  tag fix_id: 'F-6467r2_fix'
  tag 'documentable'
  tag ia_controls: 'DCBP-1, ECAN-1, ECIC-1, IAIA-1, PECS-1, PECS-2, PEDD-1'
end
