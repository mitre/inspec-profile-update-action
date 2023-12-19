control 'SV-225236' do
  title 'Software utilizing .Net 4.0 must be identified and relevant access controls configured.'
  desc 'With the advent of .Net 4.0, the .Net framework no longer directly configures or enforces security policy for .Net applications.  This task is now relegated to the operating system layer and the security protections built-in to .Net application "runtime hosts" that run on the O.S. 

Examples of these .Net "runtime hosts" include; Internet Explorer, Windows Shell, ASP.NET, Database Engines or any other "runtime hosts" that utilize .Net and load the .Net CLR.

Security protections include utilizing runtime host security controls such as sandboxing to restrict or control application behavior as designed or required.  

To compensate for these design changes, Windows provides native solutions such as Software Security Policies (SSP) and Application Locker (AL) which are technologies that can be implemented via Group Policy (GPO).  SSP, AL and similar third party solutions serve to restrict execution of applications, scripts and libraries based upon cryptographic hash, security zones, path and certificate values that are associated with the application files.  Additionally, application developers will utilize "sandboxing" techniques within their code in order to isolate 3rd party code libraries from critical system resources.

In order to assign protections to .Net 4.0 applications, the applications must first be identified and the appropriate hosting security mechanisms configured to accomplish that task.  

.Net STIG guidance cannot be applied if .Net applications are not identified and documented.  The lack of an application inventory introduces confidentiality, availability and integrity vulnerabilities to the system.'
  desc 'check', 'This requirement does not apply to the "caspol.exe" assembly or other assemblies provided with the Windows OS or the Windows Secure Host Baseline (SHB).

Ask the system administrator to provide documentation that identifies:

- Each .Net 4.0 application they run on the system.
- The .Net runtime host that invokes the application. 
- The security measures employed to control application access to system resources or user access to application.

If all .Net applications, runtime hosts and security protections have been documented or if there are no .Net 4.0 applications existing on the system, this is not a finding.

If there is no documentation that identifies the existence of .NET 4.0 applications or the lack thereof, this is a finding.

If the runtime hosts have not been identified, this is a finding.

If the security protections have not been identified, this is a finding.'
  desc 'fix', 'Document the existence of all .Net 4.0 applications that are not provided by the host Windows OS or the Windows Secure Host Baseline (SHB).

Document the corresponding runtime hosts that are used to invoke the applications.

Document the applications security control requirements (restricting application access to resources or user access to the application).'
  impact 0.5
  ref 'DPMS Target Microsoft DotNet Framework 4-0'
  tag check_id: 'C-26935r468023_chk'
  tag severity: 'medium'
  tag gid: 'V-225236'
  tag rid: 'SV-225236r615940_rule'
  tag stig_id: 'APPNET0070'
  tag gtitle: 'SRG-APP-000431'
  tag fix_id: 'F-26923r468024_fix'
  tag 'documentable'
  tag legacy: ['SV-41030', 'V-30986']
  tag cci: ['CCI-002530']
  tag nist: ['SC-39']
end
