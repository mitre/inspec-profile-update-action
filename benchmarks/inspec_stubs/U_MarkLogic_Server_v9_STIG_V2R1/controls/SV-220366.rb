control 'SV-220366' do
  title 'MarkLogic Server, when utilizing PKI-based authentication, must validate certificates by performing RFC 5280-compliant certification path validation.'
  desc 'The DoD standard for authentication is DoD-approved PKI certificates.

A certificate’s certification path is the path from the end entity certificate to a trusted root certification authority (CA). Certification path validation is necessary for a relying party to make an informed decision regarding acceptance of an end entity certificate. Certification path validation includes checks such as certificate issuer trust, time validity, and revocation status for each certificate in the certification path. Revocation status information resource/or CA and subject certificates in a certification path is commonly provided via certificate revocation lists (CRLs) or online certificate status protocol (OCSP) responses.

Database Management Systems that do not validate certificates by performing RFC 5280-compliant certification path validation are in danger of accepting certificates that are invalid and/or counterfeit. This could allow unauthorized access to the database.'
  desc 'check', 'Review DBMS configuration to verify that certificates being accepted by the DBMS are validated by performing RFC 5280-compliant certification path validation, specifically periodic revocation list processing, with custom application code that performs these functions.

To check for existing CRLs, use the MarkLogic QConsole and execute the following XQuery command against the Security Database:

cts:uri-match("http://marklogic.com/xdmp/pki/crls/*")

If there are CRLs, then it will return which CRLs are loaded, if not then it will return an empty sequence.

If any required CRLs are missing, this is a finding.'
  desc 'fix', 'Organizations must develop a strategy for maintaining a record of CRLs that have been applied to MarkLogic as well as a strategy for regularly obtaining updated CRLs from applicable Certificate Authorities.

Use one of the following two methods to add a CRL to MarkLogic:

Option 1 - Use the MarkLogic REST API "PUT /manage/v2/certificate-revocation-lists" (requires user authenticating to the system and have security and manage-admin roles)
Using a compatible HTTP request generator (i.e., Postman or curl) construct an HTTP PUT request:
EXAMPLE:
 curl -X PUT --anyauth --user admin:admin --header "Content-Type:text/html" \\
 -d "http://crl.verisign.com/pca3.crl" \\
 http://localhost:8002/manage/v2/certificate-revocation-lists?url=url
NOTE: If the "url" param is a CRL then the request body must contain the PEM- or DER-encoded CRL. If the "url" parameter is a URL, then the request body must contain the URL from which the CRL was downloaded.

Option 2 - Use the Query Console in MarkLogic to insert the CRL using pki:insert-certificate-revocation-list() method (requires user authenticating to the system have security and manage-admin roles)
EXAMPLE:
xquery version "1.0-ml"; 
import module namespace pki = "http://marklogic.com/xdmp/pki" at "/MarkLogic/pki.xqy";
let $URI := "http://crl.verisign.com/pca3.crl"
 return
 pki:insert-certificate-revocation-list(
 $URI, 
 xdmp:document-get($URI)/binary() )'
  impact 0.5
  ref 'DPMS Target MarkLogic Server v9'
  tag check_id: 'C-22081r401549_chk'
  tag severity: 'medium'
  tag gid: 'V-220366'
  tag rid: 'SV-220366r622777_rule'
  tag stig_id: 'ML09-00-003900'
  tag gtitle: 'SRG-APP-000175-DB-000067'
  tag fix_id: 'F-22070r401550_fix'
  tag 'documentable'
  tag legacy: ['SV-110081', 'V-100977']
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
