Usage (PowerShell):
1) Open an elevated PowerShell (Run as Administrator) for access to MainModule paths.
2) Navigate to your project folder (where mock_vt_responses exists or will be created).
3) Run, for example:
   powershell -ExecutionPolicy Bypass -File .\make_mocks_for_processes.ps1 -MockDir .\vt_test_files\mock_vt_responses -Process notepad,explorer -Status malicious
4) Rerun your program with --mock-vt-dir pointing to that folder.
