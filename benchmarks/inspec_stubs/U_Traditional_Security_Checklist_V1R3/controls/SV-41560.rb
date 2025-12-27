control 'SV-41560' do
  title 'Vault/Secure Room Storage Standards - IDS Alarm Monitoring Indicators, both audible and visual (Alarm Status) must be displayed for each sensor or alarmed zone at the monitoring station.'
  desc 'Failure to meet standards for the display of audible and visual alarm indicators at the IDS monitoring station could result in an a sensor going into alarm state and not being immediately detected.  This could result in an undetected or delayed discovery of a secure room perimeter breach and the  loss or compromise of classified material.

REFERENCES:

The Information Security Oversight Office (ISOO): http://www.archives.gov/isoo/   Implementing Directive for Protection of Classified (for Executive Order 13526), 32 CFR Parts 2001 and 2003 Classified National Security Information: paragraph 2001.43 Storage, (2) Secret.

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure C, paragraph 34.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: MP-4, PE-3, PE-5, PE-6(1)

DoD Manual 5200.01, Volume 3, SUBJECT: DoD Information Security Program: Protection of Classified Information:  Appendix to Enclosure 3, paragraphs 2.b.(2)(b).

DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 2016, Chapter 5, Section 9. Intrusion Detection Systems.'
  desc 'check', 'Check that all alarm activations provide both a visual and audible indicators at the primary monitoring station.
       
TACTICAL ENVIRONMENT:  This check is applicable where Vaults/Secure Rooms are used to protect classified materials or systems in a tactical environment. The only exception will be for urgent (short term) tactical operations or other contingency situations where fixed facilities and equipment are not yet present or incapable of being used.'
  desc 'fix', 'Ensure that all alarm activations provide both a visual and audible indicator at the primary monitoring station.'
  impact 0.5
  ref 'DPMS Target Traditional Security'
  tag check_id: 'C-40051r3_chk'
  tag severity: 'medium'
  tag gid: 'V-31289'
  tag rid: 'SV-41560r3_rule'
  tag stig_id: 'IS-02.02.04'
  tag gtitle: 'Vault/Secure Room Standards - IDS Alarm Status (Audible and Visual Indicators)'
  tag fix_id: 'F-35207r2_fix'
  tag 'documentable'
  tag severity_override_guidance: 'Default CAT II:  Alarm activations do not provide BOTH visual and audible indicators.'
end
