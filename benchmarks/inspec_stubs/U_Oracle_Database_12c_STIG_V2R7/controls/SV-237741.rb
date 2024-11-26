control 'SV-237741' do
  title 'The DBMS must automatically terminate emergency accounts after an organization-defined time period for each type of account.'
  desc 'Emergency application accounts are typically created due to an unforeseen operational event or could ostensibly be used in the event of a vendor support visit where a support representative requires a temporary unique account in order to perform diagnostic testing or conduct some other support-related activity. When these types of accounts are created, there is a risk that the temporary account may remain in place and active after the support representative has left.

In the event emergency application accounts are required, the application must ensure accounts that are designated as temporary in nature shall automatically terminate these accounts after an organization-defined time period.  Such a process and capability greatly reduces the risk that accounts will be misused, hijacked, or application data compromised.

Note that user authentication and account management must be done via an enterprise-wide mechanism whenever possible.  Examples of enterprise-level authentication/access mechanisms include, but are not limited to, Active Directory and LDAP. This requirement applies to cases where it is necessary to have accounts directly managed by Oracle.

If it is possible for any temporary emergency accounts to be created and managed by Oracle, then the DBMS or application must provide or utilize a mechanism to automatically terminate such accounts after an organization-defined time period.

Emergency database accounts must be automatically terminated after an organization-defined time period in order to mitigate the risk of the account being misused.'
  desc 'check', 'If the organization has a policy, consistently enforced, forbidding the creation of emergency or temporary accounts, this is not a finding.

Check DBMS settings, OS settings, and/or enterprise-level authentication/access mechanisms settings to determine if emergency accounts are being automatically terminated by the system after an organization-defined time period. Check also for custom code (scheduled jobs, procedures, triggers, etc.) for achieving this. 

If emergency accounts are not being terminated after an organization-defined time period, this is a finding.'
  desc 'fix', 'Create a profile specifically for emergency or temporary accounts.  When creating the accounts, assign them to this profile.  Configure DBMS, OS, and/or enterprise-level authentication/access mechanisms, or implement custom code, to terminate accounts with this profile after an organization-defined time period.'
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-40960r667253_chk'
  tag severity: 'medium'
  tag gid: 'V-237741'
  tag rid: 'SV-237741r879887_rule'
  tag stig_id: 'O121-C2-018600'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-40923r667254_fix'
  tag 'documentable'
  tag legacy: ['V-61777', 'SV-76267']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
