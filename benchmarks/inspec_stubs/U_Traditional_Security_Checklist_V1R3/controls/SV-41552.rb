control 'SV-41552' do
  title 'Vault/Secure Room Storage Standards - IDS Transmission Line Security'
  desc 'Failure to meet standards for ensuring integrity of the intrusion detection system signal transmission supporting a secure room (AKA: collateral classified open storage area) containing SIPRNet assets could result in the undetected loss or compromise of classified material.

REFERENCES:

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure C, paragraph 34.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: 
MP-4, PE-3, PE-5 and PE-6

DoD Manual 5200.01, Volume 3, SUBJECT: DoD Information Security Program: Protection of Classified Information: Appendix to Enclosure 3, paragraph 2.d.(1) and (2).

DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 2016, paragraph 5-904.'
  desc 'check', 'Explanation of requirement:

Transmission lines used to carry IDS sensor alarm signals between secure rooms or areas containing SIPRNet assets and IDS monitoring equipment, shall have line supervision.

If all portions of an IDS transmission line (protecting SIPRNet assets) are run within secret or higher secure area space or secret or higher controlled access area (CAA) spaces it will not require line supervision.  
  
Check:

Check that Class I or Class II line supervision is being used IAW DoD Manual 5200.01, with the exception of portions of the transmission line running entirely through spaces or areas where unescorted access is controlled to at least the Secret level.  

In summary, if portions of the transmission line run through spaces or areas where unescorted access is not controlled to at least the Secret level -  it will require line supervision.  

The check and verification of line supervision can be obtained by viewing IDS specifications from the vendor, or by conducting a controlled test of a transmission line/signal.

TACTICAL ENVIRONMENT:  This check is applicable where Vaults/Secure Rooms are used to protect classified materials or systems in a tactical environment. The only exception will be for urgent (short term) tactical operations or other contingency situations where fixed facilities and equipment are not yet present or incapable of being used.'
  desc 'fix', 'Explanation of requirement:

Transmission lines used to carry IDS sensor alarm signals between secure rooms or areas containing SIPRNet assets and IDS monitoring equipment, shall have line supervision.

If all portions of an IDS transmission line (protecting SIPRNet assets) are run within secret or higher secure area space or secret or higher controlled access area (CAA) spaces it will not require line supervision.  
  
Fix:

Class I or Class II line supervision must be used IAW DoD Manual 5200.01 for protection of IDS transmission line signals, with the exception of portions of the transmission line running entirely through spaces or areas where unescorted access is controlled to at least the Secret level.  

In summary, if portions of the transmission line run through spaces or areas where unescorted access is not controlled to at least the Secret level -  it requires line supervision.  

Verification of line supervision can be obtained by viewing IDS specifications from the vendor, or by conducting a controlled test of a transmission line/signal.'
  impact 0.7
  ref 'DPMS Target Traditional Security'
  tag check_id: 'C-40045r5_chk'
  tag severity: 'high'
  tag gid: 'V-31284'
  tag rid: 'SV-41552r3_rule'
  tag stig_id: 'IS-02.01.11'
  tag gtitle: 'Vault/Secure Room Standards - IDS Line Security'
  tag fix_id: 'F-35201r4_fix'
  tag 'documentable'
end
