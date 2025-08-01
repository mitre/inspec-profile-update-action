control 'SV-41944' do
  title 'Vault/Secure Room Storage Standards - Automated Entry Control System (AECS) Keypad Device Protection: Keypad devices designed or installed in a manner that an unauthorized person in the immediate vicinity cannot observe the selection of input numbers.'
  desc "If someone were to successfully observe an authorized user's selection of numbers for their PIN at an entrance to a classified storage area or unclassified but sensitive computer room  it could result in an unauthorized person being able to use that same PIN to gain access. Where purely electronic (cipher type) locks are used without an access card or badge this could lead to direct access by an unauthorized person.  Where coded AECS cards and badges  are used the risk is diminished significantly as the coded badge associated with the PIN would need to be lost/stolen and subsequently recovered by someone with unauthorized knowledge of the PIN for them to be able to successfully gain access to the secured area.

REFERENCES:

The Information Security Oversight Office (ISOO): http://www.archives.gov/isoo/   Implementing Directive for Protection of Classified (for Executive Order 13526), 32 CFR Parts 2001 and 2003 Classified National Security Information: paragraph 2001.43 Storage, (2) Secret.

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure C, paragraph 34.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Control: PE-3.

DoD Manual 5200.01, Volume 3, SUBJECT: DoD Information Security Program: Protection of Classified Information:  Appendix to Enclosure 3, paragraph 3.a.(5)(c).

DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 2016, Chapter 5, Section 3, paragraph 5-314.b."
  desc 'check', 'Requirements Summary:
Keypad devices (cipher locks or PIN pads for card readers) shall be designed or installed in such a manner that an unauthorized person in the immediate vicinity cannot observe the selection of input numbers.

CHECKS:
Check to ensure that all keypad devices are properly shielded and/or that persons using these devices have been advised by site security and are aware of the risk of having someone in the vicinity view their PIN as it is entered and that they are exercising due care to shield entry of their PIN. 

Verification of employee awareness can be obtained by observing SOPs or employee training records reflecting a warning or requirement to shield entry of PINs.  

TACTICAL ENVIRONMENT:  This check is applicable where Vaults/Secure Rooms are used to protect classified materials or systems in a tactical environment. The only exception will be for urgent (short term) tactical operations or other contingency situations where fixed facilities and equipment are not yet present or incapable of being used.'
  desc 'fix', 'Ensure that keypad devices (cipher locks or PIN pads for card readers) are designed or installed in such a manner that an unauthorized person in the immediate vicinity cannot observe the selection of input numbers. During initial, annual refresher training and when key cards with PINs are issued advise persons using the keypad devices of the risk of someone overseeing their PIN and encourage them to use appropriate caution to shield their selection of numbers.'
  impact 0.3
  ref 'DPMS Target Traditional Security'
  tag check_id: 'C-40374r3_chk'
  tag severity: 'low'
  tag gid: 'V-31657'
  tag rid: 'SV-41944r3_rule'
  tag stig_id: 'IS-02.03.01'
  tag gtitle: 'Vault/Secure Room Storage Standards - Automated Entry Control System (AECS) Keypad Device Protection'
  tag fix_id: 'F-35582r2_fix'
  tag 'documentable'
end
