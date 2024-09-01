from django.shortcuts import render
from rest_framework.permissions import AllowAny
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework import status
import re
import logging
from django.utils.decorators import method_decorator
from django.http import HttpResponse
from django.http import JsonResponse
from django.middleware.csrf import get_token
from django.views.decorators.csrf import csrf_exempt
import json

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
        final_text = ""

        try:
            file_content = file.read()
            lines = file_content.splitlines()

            for line in lines:
                if job_id_pattern.search(line) and additional_patterns.search(line):
                    final_text += line.decode(errors='ignore').strip() + "\n"

        except Exception as e:
            logger.error(f'Error reading file: {e}')
            raise Exception(f"An error occurred: {e}")

        return final_text
