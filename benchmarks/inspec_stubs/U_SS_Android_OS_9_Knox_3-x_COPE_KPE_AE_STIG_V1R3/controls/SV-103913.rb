control 'SV-103913' do
  title 'Samsung Android Workspace must be configured to enable the Online Certificate Status Protocol (OCSP).'
  desc 'OCSP is a protocol for obtaining the revocation status of a certificate. It addresses problems associated with using Certificate Revocation Lists (CRLs). When OCSP is enabled, it is used prior to CRL checking. If OCSP could not get a decisive response about a certificate, it will then try to use CRL checking. The OCSP response server must be listed in the certificate information under Authority Info Access. 

This feature must be enabled for a Samsung Android device to be in the NIAP-certified Common Criteria (CC) mode of operation.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review the Samsung Android Workspace configuration settings to confirm that OCSP checking is enabled for all apps. 

This procedure is performed on the MDM Administration console only. 

On the MDM console, for the Workspace, in the "Knox certificate" group, verify that "OCSP check" is configured to "enable for all apps". 

If on the MDM console "OCSP check" is not configured to "enable for all apps", this is a finding.'
  desc 'fix', 'Configure Samsung Android Workspace to enable OCSP checking for all apps. 

On the MDM, for the Workspace, in the "Knox certificate" group, configure "OCSP check" to "enable for all apps". 

Refer to the MDM documentation to determine how to configure OCSP checking to "enable for all apps". Some may, for example, allow a wildcard string: "*" (asterisk).'
  impact 0.5
  ref 'DPMS Target SamsungAndroid9withKnox3.x-COPE KPE(AE)'
  tag check_id: 'C-93145r1_chk'
  tag severity: 'medium'
  tag gid: 'V-93827'
  tag rid: 'SV-103913r1_rule'
  tag stig_id: 'KNOX-09-001330'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-100073r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
