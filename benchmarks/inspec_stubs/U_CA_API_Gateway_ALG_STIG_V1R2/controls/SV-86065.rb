control 'SV-86065' do
  title 'The CA API Gateway providing user authentication intermediary services using PKI-based user authentication must only accept end entity certificates issued by DoD PKI or DoD-approved PKI Certification Authorities (CAs) for the establishment of protected sessions.'
  desc 'Non-DoD-approved PKIs have not been evaluated to ensure that they have security controls and identity vetting procedures in place that are sufficient for DoD systems to rely on the identity asserted in the certificate. PKIs lacking sufficient security controls and identity vetting procedures risk being compromised and issuing certificates that enable adversaries to impersonate legitimate users.

The authoritative list of DoD-approved PKIs is published at http://iase.disa.mil/pki-pke/interoperability. DoD-approved PKI CAs may include Category I, II, and III certificates. Category I DoD-Approved External PKIs are PIV issuers. Category II DoD-Approved External PKIs are Non-Federal Agency PKIs cross-certified with the Federal Bridge Certification Authority (FBCA). Category III DoD-Approved External PKIs are Foreign, Allied, or Coalition Partner PKIs.

Deploying the ALG with TLS enabled will require the installation of DoD and/or DoD-approved CA certificates in the trusted root certificate store of each proxy to be used for TLS traffic. 

This requirement focuses on communications protection for the application session, rather than for the network packet.

The CA API Gateway must import the DoD PKI CA certificate(s) as trusted by using the "Manage Certificates" task. If the certificate(s) are also intended to be used for user authentication, the configuration of a "Federated Identity Provider" that extends trust to valid certificates that are signed by the DoD PKI CA certificate(s) must be configured.'
  desc 'check', 'Log on to the CA API Gateway - Policy Manager. 

Click "Task" from the main menu and select "Manage Certificates". 

If the DoD-approved PKI CA certificates are not listed or non-approved certificates are shown, this is a finding.'
  desc 'fix', 'Log on to the CA API Gateway - Policy Manager. 

Click "Task" from the main menu and select "Manage Certificates". 

Remove all non-approved certificates and click "Add". 

Select the proper options to import the approved certificates and complete the Certificate Import Wizard, selecting the values and options defined by the organization for approved certificates.'
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71831r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71441'
  tag rid: 'SV-86065r1_rule'
  tag stig_id: 'CAGW-GW-000660'
  tag gtitle: 'SRG-NET-000355-ALG-000117'
  tag fix_id: 'F-77759r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end
