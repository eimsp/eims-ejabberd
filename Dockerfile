# It is needed to build the image of DB for ejabberd
FROM postgres:14.5
RUN  usermod -u 1000 postgres

# docker build --no-cache -t qomputer/psql:145 .

