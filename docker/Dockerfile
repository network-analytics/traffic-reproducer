# TODO: make this variable to select different python versions (and manually set a default one)
FROM python:3.12-bookworm

# Set the working directory
WORKDIR /app

# Copy the application files to the container
COPY . /app

# Create /pcap directory for config and pcap files
RUN mkdir /pcap

# Install the Python dependencies
RUN pip install -r requirements.txt

# Set the entry point command
# CMD ["python", "./main.py", "--cfg", "/pcap/traffic-reproducer.conf"]
CMD ["python", "./main.py", "-h"]
