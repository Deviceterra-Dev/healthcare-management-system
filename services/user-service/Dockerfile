# Use the official Python image from the Docker Hub
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container
COPY requirements.txt .

# Install any dependencies specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code into the container
COPY . .

# Copy the setup script and wait-for-it.sh script
COPY scripts/create_superadmin.py /app/scripts/create_superadmin.py
COPY scripts/wait-for-it.sh /app/scripts/wait-for-it.sh

# Make wait-for-it.sh executable
RUN chmod +x /app/scripts/wait-for-it.sh

# Expose the port the application runs on
EXPOSE 5000

# Define environment variables
ENV NAME UserService
ENV SUPERADMIN_EMAIL=superadmin@example.com
ENV SUPERADMIN_PASSWORD=superadminpassword
ENV MONGO_URI=mongodb://mongo:27017/user_service

# Command to wait for MongoDB to be ready, run the setup script, and start the Flask application with Gunicorn
CMD ["/app/scripts/wait-for-it.sh", "mongo:27017", "--", "sh", "-c", "python /app/scripts/create_superadmin.py && gunicorn -w 4 -b 0.0.0.0:5000 run:app"]
