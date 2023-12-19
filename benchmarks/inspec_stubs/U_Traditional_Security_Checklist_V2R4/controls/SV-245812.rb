control 'SV-245812' do
  title 'Vault/Secure Room Storage Standards - Masking of IDS Sensors Displayed at the Intrusion Detection System (IDS) Monitoring Station'
  desc 'Failure to meet standards for the display of masked alarm sensors at the IDS monitoring station could result in the location with masked or inactive sensors not being properly supervised.  This could result in an undetected breach of a secure room perimeter and the undetected loss or compromise of classified material.

REFERENCES:

The Information Security Oversight Office (ISOO): http://www.archives.gov/isoo/   Implementing Directive for Protection of Classified (for Executive Order 13526), 32 CFR Parts 2001 and 2003 Classified National Security Information: paragraph 2001.43 Storage, (2) Secret.

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure C, paragraph 34.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: MP-4, PE-3, PE-5, PE-6(1)

DoD Manual 5200.01, Volume 3, SUBJECT: DoD Information Security Program: Protection of Classified Information:  Appendix to Enclosure 3, paragraphs 2d.(5) and (6).

DoD 5220.22-M (NISPOM), Incorporating Change 2, 18 May 2016, Chapter 5, Section 9. Intrusion Detection Systems.'
  desc 'check', 'Shunting or masking of any secure room IDS internal zone or sensor must be appropriately logged or recorded in the system archive. A shunted or masked internal zone or sensor must be displayed as such at the monitor station throughout the period the condition exists whenever there is a system (IDS) survey of zones or sensors.

TACTICAL ENVIRONMENT:  This check is applicable where Vaults/Secure Rooms are used to protect classified materials or systems in a tactical environment. The only exception will be for urgent (short term) tactical operations or other contingency situations where fixed facilities and equipment are not yet present or incapable of being used.'
  desc 'fix', 'Shunting or masking of any secure room IDS internal zone or sensor must be appropriately logged or recorded in the system archive. A shunted or masked internal zone or sensor must be displayed as such at the monitor station throughout the period the condition exists whenever there is a system (IDS) survey of zones or sensors.'
  impact 0.5
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49243r770096_chk'
  tag severity: 'medium'
  tag gid: 'V-245812'
  tag rid: 'SV-245812r822868_rule'
  tag stig_id: 'IS-02.02.03'
  tag gtitle: 'IS-02.02.03'
  tag fix_id: 'F-49198r770097_fix'
  tag 'documentable'
  tag legacy: ['V-31286', 'SV-41554r3_rule']
end
