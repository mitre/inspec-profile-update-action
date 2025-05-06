control 'SV-25026' do
  title 'DBMS authentication should require use of a DoD PKI certificate.'
  desc 'In a properly configured DBMS, access controls defined for data access and DBMS management actions are assigned based on the user identity and job function. Unauthenticated or falsely authenticated access leads directly to the potential unauthorized access, misuse and lost accountability of data and activities within the DBMS. Use of PKI certificates for authentication to the DBMS provides a robust mechanism to ensure identity to authorize access to the DBMS.'
  desc 'check', 'If user access to the DBMS is via a portal or mid-tier system or product and PKI-authentication occurs at the portal/mid-tier, this check is Not a Finding.

Review the list of all DBMS accounts and their authentication methods.

This list is usually available from a system view or table and is easily gained from a simple SQL query.

If any accounts are listed with an authentication method other than a PKI certificate, this is a Finding.

For MAC 3 systems, if identification and authentication is not accomplished using the DoD PKI Class 3 certificate and hardware security token (when available) at minimum, this is a Finding.

For MAC 1 and 2 systems, if identification and authentication is not accomplished using the DoD PKI Class 3 or 4 certificate and hardware security token (when available) or an NSA-certified product at minimum, this is a Finding.'
  desc 'fix', 'Implement PKI authentication for all accounts defined within the database where applicable.

Applications may use host system (server) certificates to authenticate.

For MAC 3 systems, use of the DoD PKI Class 3 certificate and hardware security token (when available) at minimum is required.

For MAC 1 and 2 systems, use of the DoD PKI Class 3 or 4 certificate and hardware security token (when available) or an NSA-certified product at minimum is required.'
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-1055r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3810'
  tag rid: 'SV-25026r1_rule'
  tag stig_id: 'DG0065-ORACLE11'
  tag gtitle: 'DBMS PKI authentication'
  tag fix_id: 'F-2540r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
