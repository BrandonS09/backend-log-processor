from django.shortcuts import render
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework import status
import re
import logging
import mmap
from django.utils.decorators import method_decorator
from django.core.files.uploadedfile import UploadedFile
from django.core.files.base import ContentFile
import json
from django.http import HttpResponse
from django.http import JsonResponse
from django.middleware.csrf import get_token
from django.views.decorators.csrf import csrf_exempt

logger = logging.getLogger(__name__)

def csrf_token_view(request):
    return JsonResponse({'csrfToken': get_token(request)})

@method_decorator(csrf_exempt, name='dispatch')
class FileUploadView(APIView):
    parser_classes = (MultiPartParser, FormParser)
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        logger.debug('POST request received.')

        file_obj = request.FILES.get('file')
        job_id_pattern = request.POST.get('jobIdPattern', '').encode()
        additional_patterns_input = request.POST.get('additionalPatterns', '')

        logger.debug(f'File: {file_obj}')
        logger.debug(f'Job ID Pattern: {job_id_pattern}')
        logger.debug(f'Additional Patterns Input: {additional_patterns_input}')

        if file_obj and file_obj.name.endswith('.txt'):
            try:
                additional_patterns = self.compile_patterns(json.loads(additional_patterns_input))
                filtered_text = self.parse_file(file_obj, job_id_pattern, additional_patterns)
                response = HttpResponse(filtered_text, content_type='text/plain')
                response['Content-Disposition'] = 'attachment; filename="processed_file.txt"'
                logger.debug('File processed successfully.')
                return response
            except Exception as e:
                logger.error(f'Error processing file: {e}')
                return Response({'message': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            logger.error('Invalid file type.')
            return Response({'message': 'Invalid file type. Please upload a .txt file.'}, status=status.HTTP_400_BAD_REQUEST)

    def compile_patterns(self, patterns):
        try:
            # Join patterns with '|' and escape special characters
            compiled_patterns = '|'.join([re.escape(pattern.strip()) for pattern in patterns])
            logger.debug(f'Compiled Patterns: {compiled_patterns}')
            return re.compile(compiled_patterns.encode(), re.IGNORECASE)
        except re.error as e:
            logger.error(f'Error compiling patterns: {e}')
            raise ValueError(f"Invalid regular expression: {e}")

    def parse_file(self, file, job_id_pattern, additional_patterns):
        jobid_pattern = re.compile(job_id_pattern, re.IGNORECASE)
        final_text = ""

        try:
            mmapped_file = mmap.mmap(file.file.fileno(), 0, access=mmap.ACCESS_READ)
            while True:
                line = mmapped_file.readline()
                if not line:
                    break
                if jobid_pattern.search(line) and additional_patterns.search(line):
                    final_text += line.decode(errors='ignore').strip() + "\n"
            mmapped_file.close()
        except Exception as e:
            logger.error(f'Error reading file: {e}')
            raise Exception(f"An error occurred: {e}")

        return final_text
# @method_decorator(csrf_exempt, name='dispatch')
# class FileUploadView(APIView):
#     parser_classes = (MultiPartParser, FormParser)
#     permission_classes = [AllowAny]

#     def post(self, request, *args, **kwargs):
#         file_obj = request.FILES.get('file')

#         if file_obj and file_obj.name.endswith('.txt'):
#             try:
#                 filtered_text = self.parse_file(file_obj)
#                 response = HttpResponse(filtered_text, content_type='text/plain')
#                 response['Content-Disposition'] = f'attachment; filename="processed_file.txt"'
#                 return response
#             except Exception as e:
#                 return Response({'message': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
#         else:
#             return Response({'message': 'Invalid file type. Please upload a .txt file.'}, status=status.HTTP_400_BAD_REQUEST)

#     def parse_file(self, file: UploadedFile) -> str:
#         jobid_pattern = re.compile(rb'\s*P00014194\.669E28F7\.636: \[', re.IGNORECASE)
#         additional_patterns = re.compile(
#             rb': \[recent action|: \[status|: \[print status|FEI - \*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\* New Job received |FEI - JOB_START |FEI - JOB_STARTED|FEI - JOB_END |FEI - JOB_CANCEL|: \[last joblog event|jmi_print_job_ex6: \[|: \[job release state|: \[queued for printing|: \[PQM',
#           re.IGNORECASE)
#         final_text = ""

#         try:
#             mmapped_file = mmap.mmap(file.file.fileno(), 0, access=mmap.ACCESS_READ)
#             while True:
#                 line = mmapped_file.readline()
#                 if not line:
#                     break
#                 if jobid_pattern.search(line) and additional_patterns.search(line):
#                     final_text += line.decode(errors='ignore').strip() + "\n"
#             mmapped_file.close()
#         except FileNotFoundError:
#             raise FileNotFoundError("Error: The file could not be found.")
#         except Exception as e:
#             raise Exception(f"An error occurred: {e}")

#         return final_text
