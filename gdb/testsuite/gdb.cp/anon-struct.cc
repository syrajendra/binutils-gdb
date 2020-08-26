/* This testcase is part of GDB, the GNU debugger.

   Copyright 2011-2020 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

class C {
public:
  C() {}
  ~C() {}
};

#ifdef __clang__
struct t {
  t() {}
  ~t() {}
  C m;
};
typedef struct t t_t;
t_t v;
#else
typedef struct {
  C m;
} t;

t v;
#endif

namespace X {
  class C2 {
  public:
    C2() {}
  };

#ifdef __clang__
  struct t2 {
    t2() {}
    ~t2() {}
    C2 m;
  };
  typedef struct t2 t2_t;
  t2_t v2;
#else
  typedef struct {
    C2 m;
  } t2;

  t2 v2;
#endif
}

template<class T>
class C3 {
public:
  ~C3() {}
};

#ifdef __clang__
struct t3 {
  t3() {}
  ~t3() {}
  C3<int> m;
} ;
typedef struct t3 t3_t;
t3_t v3;
#else
typedef struct {
  C3<int> m;
} t3;

t3 v3;

#endif
int main()
{
}
