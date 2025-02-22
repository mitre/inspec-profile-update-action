control 'SV-42205' do
  title 'Vault/Secure Room Storage Standards - Automated Entry Control System (AECS) Door Locks: Electric Strikes and/or Magnetic Locking devices used in access control systems shall be heavy duty, industrial grade and be configured to fail secure in the event of a total loss of power (primary and backup).'
  desc 'There are a variety of locking mechanisms that may be used to secure both primary and secondary doors for vaults and classified open storage areas (secure rooms).  While the primary access door is to be secured with an appropriate combination lock when closed; during working hours an AECS using electric strikes or magnetic locks, electrical, mechanical, or electromechanical access control devices, or standard keyed locks may be used to facilitate frequent access to the secured space by employees vetted for unescorted access.  Where electrically actuated locks are used, locking mechanisms must be properly configured and controlled to ensure they fail only in a secure state during partial or total loss of power (primary and backup).  Failure to provide for these considerations could result in the loss or compromise of classified material.

REFERENCES:

The Information Security Oversight Office (ISOO): http://www.archives.gov/isoo/   Implementing Directive for Protection of Classified (for Executive Order 13526), 32 CFR Parts 2001 and 2003 Classified National Security Information: paragraph 2001.43 Storage, (2) Secret.

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure C, paragraph 34.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: PE-3, and PE-6.

DoD Manual 5200.01, Volume 3, SUBJECT: DoD Information Security Program: Protection of Classified Information:  Appendix to Enclosure 3, paragraph 3.a.(5)(e).

DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 2016, Chapter 5, Section 3, paragraphs 5-312, 5-313, and 5-314.'
  desc 'check', 'Vault/Secure Room Storage Standards - Automated Entry Control System (AECS) Door Lock Standards for Areas Containing SIPRNet Assets. 

Check to ensure the following configuration and control considerations are used according to the types of locking mechanisms being used, as specified in each check:

Check #1.  Electric Strikes and/or Magnetic Locking devices used in access control systems shall be heavy duty, industrial grade.  

Check #2.  Backup batteries and/or emergency power generators should be connected to AECS components; however, the total loss of power (primary and emergency) should also be planned for.  

Check #3. When used on secure rooms, vaults or areas protecting SIPRNet equipment, electric strikes on doors will be set to fail secure in the event of power disruption.  

Check #4. On the primary ingress/egress door to secure rooms (which contains the combination lock) the strike may be set to fail open to facilitate access to the room in emergencies only if the door is under continuous visual observation when the combination lock is not secure.  In this instance the combination lock will be immediately secured and subsequently opened as required to allow access to the room. 

Check #5. As an alternative the strike on the primary access door (only those under continuous visual control) may be set to fail secure and configured to allow for opening of the strike lock with a key.  

Check #6. Keys for locks as discussed in check 5 will be strictly controlled, inventoried periodically and not issued to individuals for personal retention. 

Check #7. KEYS TO SECURE ROOMS WILL NOT BE REMOVED FROM THE SITE.  

Check #8. When Magnetic Locks (Mag locks) are used on primary access doors the total loss of ALL power (primary and backup) will cause the lock to fail open.  Therefore doors with mag locks installed MUST BE UNDER CONTINUOUS VISUAL OBSERVATION WHEN THE COMBINATION LOCK IS OPEN.

Check #9. Where Mag locks are used on primary access doors and upon a total power failure  - the combination lock will be immediately secured and subsequently opened as required to allow access to the room.  

Check #10. Secondary doors not used for access (emergency egress only) should use standard locking door latches rather than electric strikes or mag locks.  

Check #11. Access hardware on the side of the secondary door that is external to the room must be removed to prevent use of secondary doors for routine ingress.  

Check #12. In the event a mag lock or electric strike is used on a secondary door, the door must be configured to be locked during a power disruption.  This can be accomplished with internal sliding deadbolt locks or lockable door latches.  Electric strikes on secondary doors should be set to fail secure.  Any secondary door secured with Mag Locks must be under CONTINUOUS visual observation when the interior deadbolt locks are not engaged.  Deadbolt locks must not be engaged while the room is occupied - for life safety, but will be secured upon closing the secure room or area.
                            
TACTICAL ENVIRONMENT:  This check is applicable where Secure Rooms are used to protect classified materials or systems in a tactical environment. The only exception will be for urgent (short term) tactical operations or other contingency situations where fixed facilities and equipment are not yet present or incapable of being used.'
  desc 'fix', 'Vault/Secure Room Storage Standards - Automated Entry Control System (AECS) Door Locks. Ensure the following configuration and control considerations are used as appropriate for the type of locks being used in access control systems protecting SIPRNet assets:

1.  Electric Strikes and/or Magnetic Locking devices used in access control systems shall be heavy duty, industrial grade.  

2.  Backup batteries and/or emergency power generators should be connected to (AECS) components; however, the total loss of power should be planned for.  

3. When used on secure rooms, vaults, or areas protecting SIPRNet equipment; electric strikes on doors will be set to fail secure in the event of power disruption.  

4. On the primary ingress/egress door to secure rooms (which contains the combination lock) the strike may be set to fail open to facilitate access to the room in emergencies only if the door is under continuous visual observation when the combination lock is not secure.  In this instance the combination lock will be immediately secured and subsequently opened as required to allow access to the room. 

5. As an alternative the strike on the primary access door (under continuous visual control) may be set to fail secure and configured to allow for opening of the strike lock with a key.  

6. Keys for such locks will be strictly controlled, inventoried periodically and not issued to individuals for retention. 

7. KEYS TO SECURE ROOMS WILL NOT BE REMOVED FROM THE SITE.

8. When Magnetic Locks (Mag locks) are used on primary access doors the total loss of ALL power (primary and backup) will cause the lock to fail open.  Therefore doors with mag locks installed must be under continuous visual observation when the combination lock is open.  

9. Where Mag locks are used on primary access doors and upon a total power failure  - the combination lock will be immediately secured and subsequently opened as required to allow access to the room.
  
10. Secondary doors not used for access (emergency egress only) should use standard locking door latches rather than electric strikes or mag locks.  

11. Access hardware on the side of the door that is external to the room must be removed to prevent use of secondary doors for routine ingress.  

12. In the event a mag lock is used on a secondary door, the door must be configured to be locked during a power disruption.  This can be accomplished with internal sliding deadbolt locks or supplemental door latches.  Any secondary door secured with Mag Locks must be under CONTINUOUS  visual observation when the interior deadbolt locks are not engaged.  Deadbolt locks must not be engaged while the room is occupied - for life safety, but will be secured upon closing the secure room or area. 

Always be sure to coordinate door locking and emergency egress considerations with supporting facility risk management(fire/safety) personnel.'
  impact 0.5
  ref 'DPMS Target Traditional Security'
  tag check_id: 'C-40607r7_chk'
  tag severity: 'medium'
  tag gid: 'V-31908'
  tag rid: 'SV-42205r3_rule'
  tag stig_id: 'IS-02.02.10'
  tag gtitle: 'Vault/Secure Room Storage Standards - Automated Entry Control System (AECS) Door Locks'
  tag fix_id: 'F-35846r4_fix'
  tag 'documentable'
end
