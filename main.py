# from fastapi import FastAPI, HTTPException
# from pydantic import BaseModel
# from typing import List, Optional
# import os
# import json
# from scanner.sqli_scanner import scan_directory as scan_sqli_directory
# from scanner.xss_scanner import scan_directory as scan_xss_directory
# from scanner.file_inclusion_scanner import scan_directory as scan_file_inclusion_directory
# from scanner.csrf_scanner import scan_directory as scan_csrf_directory
# from scanner.command_injection_scanner import scan_directory as scan_command_injection_directory

# app = FastAPI(title="Static Vulnerability Scanner API")

# # Request models
# class ScanRequest(BaseModel):
#     scan_folder: str
#     vuln_types: List[str] = ["sqli", "xss", "file_inclusion", "csrf", "command_injection"]
#     file_types: List[str] = [".php", ".js", ".html"]
#     save_report: bool = False

# class FileFilterRequest(BaseModel):
#     directory: str
#     file_types: List[str]

# # Response models
# class Vulnerability(BaseModel):
#     file: str
#     line: int
#     issue: str
#     code: str

# class ScanResponse(BaseModel):
#     vulnerabilities: List[Vulnerability]
#     message: str
#     report_path: Optional[str] = None

# class FileFilterResponse(BaseModel):
#     files: List[str]
#     message: str

# @app.post("/api/scan", response_model=ScanResponse)
# async def scan_combined_endpoint(request: ScanRequest):
#     """
#     Scan a directory for multiple types of vulnerabilities
#     """
#     # Validate directory
#     if not os.path.isdir(request.scan_folder):
#         raise HTTPException(status_code=400, detail="Invalid directory path")

#     # Clean input
#     vuln_types = [v.strip().lower() for v in request.vuln_types]
#     file_types = [ft.strip() for ft in request.file_types]

#     results = []

#     print(f"\n🔍 Scanning folder: {request.scan_folder}")
#     print(f"🔎 Vulnerability types: {vuln_types}")
#     print(f"📄 File types: {file_types}\n")

#     # Run scans based on requested vulnerability types
#     if 'sqli' in vuln_types:
#         print("Starting SQL Injection scan...")
#         results.extend(scan_sqli_directory(request.scan_folder))

#     if 'xss' in vuln_types:
#         print("Starting XSS scan...")
#         results.extend(scan_xss_directory(request.scan_folder))

#     if 'file_inclusion' in vuln_types:
#         print("Starting File Inclusion scan...")
#         results.extend(scan_file_inclusion_directory(request.scan_folder))

#     if 'csrf' in vuln_types:
#         print("Starting CSRF scan...")
#         results.extend(scan_csrf_directory(request.scan_folder))

#     if 'command_injection' in vuln_types:
#         print("Starting Command Injection scan...")
#         results.extend(scan_command_injection_directory(request.scan_folder))

#     response = ScanResponse(
#         vulnerabilities=results,
#         message="No vulnerabilities found" if not results else f"Found {len(results)} potential vulnerabilities"
#     )

#     # Save report if requested
#     if request.save_report:
#         report_path = 'reports/scan_report.json'
#         try:
#             os.makedirs(os.path.dirname(report_path), exist_ok=True)
#             with open(report_path, 'w') as f:
#                 json.dump(results, f, indent=4)
#             response.report_path = report_path
#         except Exception as e:
#             raise HTTPException(status_code=500, detail=f"Failed to save report: {str(e)}")

#     return response

# @app.post("/api/filter-files", response_model=FileFilterResponse)
# async def filter_files_endpoint(request: FileFilterRequest):
#     """
#     Filter files in a directory by specified extensions
#     """
#     if not os.path.isdir(request.directory):
#         raise HTTPException(status_code=400, detail="Invalid directory path")

#     matching_files = []
#     for root, _, files in os.walk(request.directory):
#         for file in files:
#             if any(file.endswith(ext) for ext in request.file_types):
#                 matching_files.append(os.path.join(root, file))

#     return FileFilterResponse(
#         files=matching_files,
#         message=f"Found {len(matching_files)} matching files"
#     )

# @app.get("/health")
# async def health_check():
#     """
#     Health check endpoint
#     """
#     return {"status": "healthy"}


from fastapi import FastAPI, HTTPException, UploadFile, File
from pydantic import BaseModel, ValidationError
from typing import List, Optional
import os
import json
import shutil
import tempfile
import zipfile
from fastapi.middleware.cors import CORSMiddleware
from scanner.sqli_scanner import scan_directory as scan_sqli_directory
from scanner.xss_scanner import scan_directory as scan_xss_directory
from scanner.file_inclusion_scanner import scan_directory as scan_file_inclusion_directory
from scanner.csrf_scanner import scan_directory as scan_csrf_directory
from scanner.command_injection_scanner import scan_directory as scan_command_injection_directory

app = FastAPI(title="Static Vulnerability Scanner API")

# CORS configuration to allow frontend requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5500"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Response models (unchanged)
class Vulnerability(BaseModel):
    file: str
    line: int
    issue: str
    code: str

class ScanResponse(BaseModel):
    vulnerabilities: List[Vulnerability]
    message: str
    report_path: Optional[str] = None

class FileFilterRequest(BaseModel):
    directory: str
    file_types: List[str]

class FileFilterResponse(BaseModel):
    files: List[str]
    message: str

@app.post("/api/scan", response_model=ScanResponse)
async def scan_combined_endpoint(file: UploadFile = File(...), vuln_types: str = "[]", file_types: str = "[]", save_report: bool = False):
    """
    Scan an uploaded file or archive for multiple types of vulnerabilities
    """
    try:
        print(f"Received file: {file.filename}")
        print(f"Received vuln_types: {vuln_types}")
        print(f"Received file_types: {file_types}")
        print(f"Received save_report: {save_report}")

        # Create a temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            # Save the uploaded file
            file_path = os.path.join(temp_dir, file.filename)
            with open(file_path, "wb") as buffer:
                shutil.copyfileobj(file.file, buffer)

            # Determine scan target
            scan_folder = temp_dir
            if file.filename.endswith(('.zip', '.tar', '.gz', '.rar', '.7z')):
                try:
                    with zipfile.ZipFile(file_path, 'r') as zip_ref:
                        zip_ref.extractall(temp_dir)
                except Exception as e:
                    raise HTTPException(status_code=400, detail=f"Failed to extract file: {str(e)}")
            else:
                # For single files, use the directory containing the file
                scan_folder = os.path.dirname(file_path)

            # Parse JSON inputs
            try:
                vuln_types_list = json.loads(vuln_types) if vuln_types else []
                file_types_list = json.loads(file_types) if file_types else [".php", ".js", ".html"]
            except json.JSONDecodeError as e:
                raise HTTPException(status_code=422, detail=f"Invalid JSON format: {str(e)}")

            # Clean and validate input
            valid_vuln_types = {"sqli", "xss", "file_inclusion", "csrf", "command_injection"}
            vuln_types_list = [v.strip().lower() for v in vuln_types_list if v.strip().lower() in valid_vuln_types]
            if not vuln_types_list:
                vuln_types_list = list(valid_vuln_types)  # Default to all
            file_types_list = [ft.strip() for ft in file_types_list]

            results = []

            print(f"\n🔍 Scanning folder: {scan_folder}")
            print(f"🔎 Vulnerability types: {vuln_types_list}")
            print(f"📄 File types: {file_types_list}\n")

            # Run scans based on requested vulnerability types
            if 'sqli' in vuln_types_list:
                print("Starting SQL Injection scan...")
                try:
                    results.extend([Vulnerability(**vuln) for vuln in scan_sqli_directory(scan_folder)])
                except ValidationError as e:
                    print(f"Invalid data from SQLi scanner: {str(e)}")
                    pass

            if 'xss' in vuln_types_list:
                print("Starting XSS scan...")
                try:
                    results.extend([Vulnerability(**vuln) for vuln in scan_xss_directory(scan_folder)])
                except ValidationError as e:
                    print(f"Invalid data from XSS scanner: {str(e)}")
                    pass

            if 'file_inclusion' in vuln_types_list:
                print("Starting File Inclusion scan...")
                try:
                    results.extend([Vulnerability(**vuln) for vuln in scan_file_inclusion_directory(scan_folder)])
                except ValidationError as e:
                    print(f"Invalid data from File Inclusion scanner: {str(e)}")
                    pass

            if 'csrf' in vuln_types_list:
                print("Starting CSRF scan...")
                try:
                    results.extend([Vulnerability(**vuln) for vuln in scan_csrf_directory(scan_folder)])
                except ValidationError as e:
                    print(f"Invalid data from CSRF scanner: {str(e)}")
                    pass

            if 'command_injection' in vuln_types_list:
                print("Starting Command Injection scan...")
                try:
                    results.extend([Vulnerability(**vuln) for vuln in scan_command_injection_directory(scan_folder)])
                except ValidationError as e:
                    print(f"Invalid data from Command Injection scanner: {str(e)}")
                    pass

            response = ScanResponse(
                vulnerabilities=results,
                message="No vulnerabilities found" if not results else f"Found {len(results)} potential vulnerabilities"
            )

            # Save report if requested
            if save_report:
                report_path = 'reports/scan_report.json'
                try:
                    os.makedirs(os.path.dirname(report_path), exist_ok=True)
                    with open(report_path, 'w') as f:
                        json.dump([vuln.dict() for vuln in results], f, indent=4)
                    response.report_path = report_path
                except Exception as e:
                    raise HTTPException(status_code=500, detail=f"Failed to save report: {str(e)}")

            return response
    except Exception as e:
        print(f"Error in scan endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")

@app.post("/api/filter-files", response_model=FileFilterResponse)
async def filter_files_endpoint(request: FileFilterRequest):
    """
    Filter files in a directory by specified extensions
    """
    if not os.path.isdir(request.directory):
        raise HTTPException(status_code=400, detail="Invalid directory path")

    matching_files = []
    for root, _, files in os.walk(request.directory):
        for file in files:
            if any(file.endswith(ext) for ext in request.file_types):
                matching_files.append(os.path.join(root, file))

    return FileFilterResponse(
        files=matching_files,
        message=f"Found {len(matching_files)} matching files"
    )

@app.get("/health")
async def health_check():
    """
    Health check endpoint
    """
    return {"status": "healthy"}