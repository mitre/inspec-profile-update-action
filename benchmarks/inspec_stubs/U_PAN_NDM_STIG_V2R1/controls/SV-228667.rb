control 'SV-228667' do
  title 'The Palo Alto Networks security platform must accept and verify Personal Identity Verification (PIV) credentials.'
  desc 'The use of PIV credentials facilitates standardization and reduces the risk of unauthorized access.

DoD has mandated the use of the CAC to support identity management and personal authentication for systems covered under HSPD 12 and as a primary component of layered protection for national security systems.'
  desc 'check', 'Go to Device >> Certificate Management >> Certificates.
If no DOD CA certificates and subordinate certificates are imported, this is a finding.

Go to Device >> Setup >> Management.
In the Authentication Settings pane, if the Certificate Profile field is  blank, this is a finding.

View the Certificate Profile, if it does not list the DOD CA certificates and subordinate certificates, this is a finding.

If the Use OCSP checkbox is not selected, this is a finding.'
  desc 'fix', 'Import the DOD CA certificates and subordinate certificates for all of the certificate authorities.
Go to Device >> Certificate Management >> Certificates.
Select the Import icon at the bottom of the pane.
In the Import Certificate window, complete the required information.
Select "OK".

Create a certificate profile.
Go to Device >> Setup >> Management.
In the Authentication Settings pane, select the select the "Edit" icon (the gear symbol in the upper-right corner).
In the Authentication Settings window, complete the required information.
In the Authentication Profile field, select "None".
In the Certificate Profile field, select "New Certificate Profile".  This will change the Authentication Settings window to the Certificate Profile window.
Leave the username field blank.
Leave the domain field blank.
 
In the Certificate Profile window, complete the required fields.
In the CA Certificates section, select "Add" to import the DOD certificate authorities.
Select the Use OCSP checkbox.
When importing the top level DOD CA Certificate, for the Default OCSP URL field, add the DOD/DISA OCSP URL.
Select "OK".
Select "OK" again.
Commit changes by selecting "Commit" in the upper-right corner of the screen.
Select "OK" when the confirmation dialog appears.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks NDM'
  tag check_id: 'C-30902r513604_chk'
  tag severity: 'medium'
  tag gid: 'V-228667'
  tag rid: 'SV-228667r513606_rule'
  tag stig_id: 'PANW-NM-000110'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-30879r513605_fix'
  tag 'documentable'
  tag legacy: ['SV-77251', 'V-62761']
  tag cci: ['CCI-000366', 'CCI-001953']
  tag nist: ['CM-6 b', 'IA-2 (12)']
end
