control 'SV-245816' do
  title 'Vault/Secure Room Storage Standards - Primary IDS Monitoring Location Outside the Monitored Space'
  desc 'Failure to locate the alarm monitoring station at an external location; at a safe distance from the space being monitored, to ensure that it is not involved in any surprise attack of the alarmed space could result in a perimeter breach and the  loss or compromise of classified material with limited or no capability to immediately notify response forces.

REFERENCES:

The Information Security Oversight Office (ISOO): http://www.archives.gov/isoo/   Implementing Directive for Protection of Classified (for Executive Order 13526), 32 CFR Parts 2001 and 2003 Classified National Security Information: paragraph 2001.43 Storage, (2) Secret.

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure C, paragraph 34.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: MP-4, PE-3, PE-5, PE-6(1)

DoD Manual 5200.01, Volume 3, SUBJECT: DoD Information Security Program: Protection of Classified Information:  Appendix to Enclosure 3, paragraph 2.d.(6).

DoD 5220.22-M (NISPOM), Incorporating Change 2, 18 May 2016, Chapter 5, Section 9. Intrusion Detection Systems, paragraphs 5-900 and 5-902.'
  desc 'check', 'Check to ensure that primary monitoring of alarms for secure rooms or spaces containing SIPRNet equipment is located outside of the protected space.  It is allowable to monitor alarms within the protected space if this is only used for supplemental/secondary monitoring.  Ideally alarms will be monitored from the same location that police/guards or other response forces are contacted and dispatched, although this is not required if there are procedures and means for the monitoring station personnel to notify security response forces in a timely manner.
                                                     TACTICAL ENVIRONMENT:  This check is applicable where Vaults/Secure Rooms are used to protect classified materials or systems in a tactical environment. The only exception will be for urgent (short term) tactical operations or other contingency situations where fixed facilities and equipment are not yet present or incapable of being used.'
  desc 'fix', 'Ensure that primary monitoring of alarms for secure rooms or spaces containing SIPRNet equipment is located outside of the protected space.'
  impact 0.5
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49247r770108_chk'
  tag severity: 'medium'
  tag gid: 'V-245816'
  tag rid: 'SV-245816r822873_rule'
  tag stig_id: 'IS-02.02.07'
  tag gtitle: 'IS-02.02.07'
  tag fix_id: 'F-49202r770109_fix'
  tag 'documentable'
  tag legacy: ['V-31293', 'SV-41564r3_rule']
end
