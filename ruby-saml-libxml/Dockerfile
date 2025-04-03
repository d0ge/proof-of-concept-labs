FROM ruby:3.4.2

# Set working directory
WORKDIR /app
# Copy app code
COPY . .

# Install dependencies
RUN bundle install

# Expose the port used by Sinatra
EXPOSE 9292

# Start the app with Rack
CMD ["bundle", "exec", "puma", "-C", "config/puma.rb"]

