control 'SV-24465' do
  title 'The Oracle software installation account should not be granted excessive host system privileges.'
  desc 'A compromise of the Oracle database process could be used to gain access to the host operating system under the security account of the process owner. Limitation of the privileges assigned to the process account can help contain access to other processes and host system resources. This can in turn help to limit any resulting malicious activity.'
  desc 'check', 'Review the Oracle process/owner account.

For UNIX Systems:

Log into the Oracle installation account and from a system prompt enter:

  groups

If root is returned in the list, this is a Finding.

For Windows Systems:

Log in using an account with administrator privileges.

Open the Services snap-in.

If the Oracle services are not assigned a dedicated OS account (view the Log on As tab), this is a Finding.

If the account is assigned group membership to other than the local administrator account and Oracle DBA groups, this is a Finding.

View user rights assigned to the service accounts.

If Deny Logon Locally is not assigned to the Oracle service account, this is a Finding.

If the service account is a domain rather than local user account, confirm with the DBA that domain resources are required and that the account is not assigned to any domain groups not required for Oracle operation (e.g. the domain users or domain administrators groups).

If the service account is a domain account and the account is assigned to domain groups not required for Oracle operations, this is a Finding.'
  desc 'fix', 'Remove root privileges from the Oracle software owner account on UNIX systems.

Create and assign a dedicated OS account for all Oracle processes (Windows).

Grant the dedicated OS account Oracle DBA privileges and assign the Deny Logon Locally user right to the dedicated OS account.'
  impact 0.5
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-29407r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3842'
  tag rid: 'SV-24465r1_rule'
  tag stig_id: 'DO0120-ORACLE11'
  tag gtitle: 'Oracle process account host system privileges'
  tag fix_id: 'F-26434r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
