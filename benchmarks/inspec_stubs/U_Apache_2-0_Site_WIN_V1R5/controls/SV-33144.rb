control 'SV-33144' do
  title 'PERL scripts must use the TAINT option.'
  desc 'PERL (Practical Extraction and Report Language) is an interpreted language optimized for scanning arbitrary text files, extracting information from those text files, and printing reports based on that information. The language is often used in shell scripting and is intended to be practical, easy to use, and efficient means of generating interactive web pages for the user. Unfortunately, many widely available freeware PERL programs (scripts) are extremely insecure. This is most readily accomplished by a malicious user substituting input to a PERL script during a POST or a GET operation.

Consequently, the founders of PERL have developed a mechanism named TAINT that protects the system from malicious input sent from outside the program. When the data is tainted, it cannot be used in programs or functions such as eval(), system(), exec(), pipes, or popen(). The script will exit with a warning message.'
  desc 'check', 'Locate the Apache httpd.conf file.

If unable to locate the file, perform a search of the system to find the location of the file.

Open the httpd.conf file with an editor such as Notepad, and search for the following uncommented directive: ScriptInterpreterSource

For any enabled ScriptInterpreterSource directives the only authorized entries are Registry-Strict or Script. If any other entry (i.e. Registry) is found, this is a finding.

For all enabled ScriptInterpreterSource directives set to Registry-Strict: open regedit then Navigate to the following location: HKEY_CLASSES_ROOT\\.pl\\Shell\\ExecCGI\\Command\\(Default) => C:\\Perl\\bin\\perl.exe –T (This entry should specify the location of the Perl.exe file). If this entry is not found, this is a finding.

For all enabled ScriptInterpreterSource directive set to Script: Search the system for all files ending with “.pl”. Open all files found with a text editor and ensure the following entry is found - #![Drive Letter]:/[Path to Perl install directory]/bin/perl.exe –T. If this entry is not found, this is a finding.

NOTE: This applies to PERL scripts that are used as part of the web server and not all PERL scripts that are on the system.
NOTE: If the mod_perl module is installed, and the directive “PerlTaintCheck on” is entered in the httpd.conf, this satisfies the requirement.'
  desc 'fix', 'Adjust the PERL scripts or the registry to include the appropriate comments.'
  impact 0.5
  ref 'DPMS Target Apache Site 2.0'
  tag check_id: 'C-33795r1_chk'
  tag severity: 'medium'
  tag gid: 'V-2272'
  tag rid: 'SV-33144r1_rule'
  tag stig_id: 'WG460 W22'
  tag gtitle: 'WG460'
  tag fix_id: 'F-29439r1_fix'
  tag 'documentable'
  tag mitigations: 'WG460 - General'
  tag mitigation_control: 'If the TAINT option cannot be used for any reason, this finding can be mitigated by the use of a third-party input validation mechanism or input validation will be included as part of the script in use. This must be documented.'
  tag responsibility: 'Web Administrator'
  tag ia_controls: 'ECSC-1'
end
