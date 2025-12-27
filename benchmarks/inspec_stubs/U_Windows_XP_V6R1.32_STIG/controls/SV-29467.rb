control 'SV-29467' do
  title 'An approved DOD virus scan program is not used and/or updated.'
  desc 'This is a Category 1 finding because Virus scan programs are a primary line of defense against the introduction of viruses and malicious code that can destroy data and even render a computer inoperable.  Utilizing the most current virus scan program provides the ability to detect this malicious code before extensive damage occurs.  Updated virus scan data files can help protect a system, because new viruses are identified by the software vendors on a monthly basis.'
  desc 'check', 'Note:   The Gold Disk checks for McAfee and Symantec Antivirus, corporate and client editions.  Due to variation of installations, manual checks may be required for verifying antivirus compliance.

V0019910 has been added as part of the Desktop STIG Update which specifically looks at McAfee and Symantec AV signature files.  If you have these programs, address them with that requirement and mark this one as N/A.

If none of the following products are installed and supported at an appropriate maintenance level, then this is a finding:

Symantec Antivirus at the following level is not installed:
            Corporate Edition Version 9.0.6 or higher  
            Corporate Edition Version 10.x or higher 
            Endpoint Protection Version 11.0 or higher

McAfee’s Antivirus Version 8.0 or higher is not installed.

                      And
The antivirus signature file is out of date. 
If the anti virus program signature file is not dated within the past 7 days, then this is a finding.

Note:  The version numbers and the date of the signature file can generally be checked by starting the antivirus program from the toolbar icon or from the Start menu.  The information may appear in the antivirus window or be available in the Help > About window.  The location varies from product to product.

Note:  E-mail versions of antivirus software are not acceptable as protection for Windows operating systems.   However, both the e-mail antivirus software and the operating system antivirus software can coexist and run on the same system.

Documentable Explanation: If a recognized antivirus product, such as Innoculator or another product is installed and has a current signature file, then this would still be a finding, but the severity code should be reduced to a Category III.'
  desc 'fix', 'Configure the system with supported, DoD-approved virus scanning software.  Ensure the signature file is current.'
  impact 0.7
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-519r1_chk'
  tag severity: 'high'
  tag gid: 'V-1074'
  tag rid: 'SV-29467r1_rule'
  tag gtitle: 'Approved DoD Virus Scan Program'
  tag fix_id: 'F-5817r1_fix'
  tag false_negatives: 'E-Mail versions of anti-virus software are not acceptable as protection for Windows operating systems.   However, both the E-Mail anti-virus software and the operating system anti-virus software can coexist and run on the same system.'
  tag false_positives: 'The scripts check for McAfee and Symantec Antivirus, corporate and client editions.  Due to variation of installations, manual checks may be required for verifying Anti-Virus compliance.'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECVP-1'
end
