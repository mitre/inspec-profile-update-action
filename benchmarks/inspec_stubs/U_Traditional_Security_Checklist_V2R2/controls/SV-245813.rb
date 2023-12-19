control 'SV-245813' do
  title 'Vault/Secure Room Storage Standards - IDS Alarm Monitoring Indicators, both audible and visual (Alarm Status) must be displayed for each sensor or alarmed zone at the monitoring station.'
  desc 'Failure to meet standards for the display of audible and visual alarm indicators at the IDS monitoring station could result in an a sensor going into alarm state and not being immediately detected.  This could result in an undetected or delayed discovery of a secure room perimeter breach and the  loss or compromise of classified material.

REFERENCES:

The Information Security Oversight Office (ISOO): http://www.archives.gov/isoo/   Implementing Directive for Protection of Classified (for Executive Order 13526), 32 CFR Parts 2001 and 2003 Classified National Security Information: paragraph 2001.43 Storage, (2) Secret.

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure C, paragraph 34.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: MP-4, PE-3, PE-5, PE-6(1)

DoD Manual 5200.01, Volume 3, SUBJECT: DoD Information Security Program: Protection of Classified Information:  Appendix to Enclosure 3, paragraphs 2.b.(2)(b).

DoD 5220.22-M (NISPOM), Incorporating Change 2, 18 May 2016, Chapter 5, Section 9. Intrusion Detection Systems.'
  desc 'check', 'Check that all alarm activations provide both visual and audible indicators at the primary monitoring station.
       
TACTICAL ENVIRONMENT:  This check is applicable where Vaults/Secure Rooms are used to protect classified materials or systems in a tactical environment. The only exception will be for urgent (short term) tactical operations or other contingency situations where fixed facilities and equipment are not yet present or incapable of being used.'
  desc 'fix', 'Ensure that all alarm activations provide both a visual and audible indicator at the primary monitoring station.'
  impact 0.5
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49244r822869_chk'
  tag severity: 'medium'
  tag gid: 'V-245813'
  tag rid: 'SV-245813r822870_rule'
  tag stig_id: 'IS-02.02.04'
  tag gtitle: 'IS-02.02.04'
  tag fix_id: 'F-49199r770100_fix'
  tag 'documentable'
  tag legacy: ['SV-41560r3_rule', 'V-31289']
end
