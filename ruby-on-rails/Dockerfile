FROM ruby:latest

RUN apt-get update -yqq && apt-get install -yqq --no-install-recommends redis-server

EXPOSE 3000
WORKDIR /rails

COPY ./Gemfile* /rails/

ENV BUNDLE_FORCE_RUBY_PLATFORM=true
ENV BUNDLE_WITHOUT=trilogy
RUN bundle install --jobs=8

COPY . /rails/

ENV RUBY_YJIT_ENABLE=1
ENV RAILS_ENV=production
ENV PORT=3000
CMD ./run.sh
