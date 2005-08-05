#!/usr/bin/env ruby
#
#  Author: Johnny Lai
#  Copyright (c) 2004 Johnny Lai
#
# =DESCRIPTION
# CMakeLists.txt generater for omnetpp type projects. Currently works with INET
# and generates IPv6Suite's OneBigExe.cmake but should work for others too. 
#

#Pattern for doing wildcard matches of filenames recursively i.e. subdirectories too 
RECURSEDIR="**/*"

#Extension of files used for message subclassing
MSGEXT=".msg"

def traverseDirectory(dir, expression, ignore = nil)
  oldpwd = Dir.pwd
  Dir.chdir(dir)
  arr = Array.new
  Dir[expression].each {|f|
    next if ignore and f =~ Regexp.new(ignore)
    arr.push(f)
  }
  arr
ensure
  Dir.chdir(oldpwd)
end

def customCommands(dir)  
  
  m = traverseDirectory(dir,RECURSEDIR+MSGEXT,"RTP|Unsupported")
  
  genSources = Array.new
  cleanSources = Array.new 
  objs = Array.new

  string = ""
  
  m.each{|msg|
    cfile = msg.to_s.gsub(MSGEXT,"_m.cc")  
    hfile = msg.to_s.gsub(MSGEXT,"_m.h")
    ofile = msg.to_s.gsub(MSGEXT, "_m.o")
    
    #Needed as we do opp_msgc gen and rest of build from top level dir only
    cfile = File.basename cfile
    hfile = File.basename hfile
    ofile = File.basename ofile

    genSources.push(cfile)
    cleanSources.push(hfile)
    objs.push(ofile)

    # ADD_CUSTOM_COMMAND(TARGET #{cwd} PRE_BUILD COMMAND ${OPP_MSGC} ARGS -h #{m})
  }

  #string += "\nOPP_WRAP_MSGC(dum dum2 #{m.join("\n")}\n)\n"
  string += "\nOPP_WRAP_MSGC_ALL()\n"

  Array[string, genSources]
end

def addSourceFiles(dir, ignorePattern)
  c = traverseDirectory(dir, RECURSEDIR+".{h,cc,cpp,c}", ignorePattern)

  includeDirs = Array.new
  c.delete_if {|f| 
    header = f =~ /\.h$/     
    includeDirs.push(File.dirname(f)) if header and not includeDirs.include? File.dirname(f) 
    header
  }
  Array[c, includeDirs]
end

# Used only by IPv6Suite
def readSourceList(filename)
  @sourceList = IO.readlines(filename)
  @sourceList.map! {|e|
    e.chomp!
    #Remove leading path so we match only on file component
    e.gsub!(/^.*\//,"")
    e
  }
  @sourceList.delete_if{|e| not e =~ /[[:alpha:]]/}
  return @sourceList
end

def addTests(dir)
  c = traverseDirectory(dir, RECURSEDIR + ".test")
  testDirs = Array.new
  c.each{ |test|
    testDirs.push(File.dirname(test)) if not testDirs.include? File.dirname(test)
  }
  testDirs
end

def writeTest(testDirs, projName)
  testDirs.each{ |d|
    open("#{d}/CMakeLists.txt","w") { |testCMake|
      testCMake.puts "LINK_LIBRARIES(#{projName} ${OPP_LIBRARIES})"
      testCMake.puts "OPP_WRAP_TEST(#{File.basename(d)})" 
    }
  }  
end

def writeCMakeList(dir, outputName, projName = nil)
  
  commonIgnore = "Unsupported|_m\.|test"
  
  ignore = @customise ? "TCP|" + commonIgnore : "RTP|" + commonIgnore

  sources, includes = addSourceFiles(dir, ignore)    
  
  projName ||= File.basename(dir)  
  
  open("#{dir}/#{outputName}","w") {  |x|

    x.puts "# -*- CMAKE -*-"
    x.puts %{#Generated by "#{$0} #{ARGV.join(" ")}"}

    if not @customise
      x.puts(sprintf("PROJECT(%s)", projName)) if projName and projName.length > 0
      
      # set_dir_props generated from customCommands requires this
      x.puts %{CMAKE_MINIMUM_REQUIRED(VERSION 2.0)} 
      x.puts "SET(CMAKEFILES_PATH #{File.dirname(File.dirname($0))+"/CMake"})"
      
      x.puts %{OPTION(BUILD_SHARED_LIBS "Build with shared libraries." ON)}
      x.puts %{SET(ONE_BIG_EXE ON)}
      x.puts("INCLUDE(${CMAKEFILES_PATH}/FindOmnet.cmake)")  
      
      x.puts("INCLUDE_DIRECTORIES(${OPP_INCLUDE_PATH})") 
      x.puts("INCLUDE_DIRECTORIES(${PROJECT_BINARY_DIR})")
    end

    customCommandsLines, genSources = customCommands(dir)
    
    x.print customCommandsLines

    #It appears that these source files properties only exist in the current
    #Dir/cmakelist.txt because in subdir's cmakelist.txt cannot use the source
    #file here as it complains source does not exist unless we also set generated property in there for these files again 
    #this does not work however
    #x.print "SET_SOURCE_FILES_PROPERTIES(${GENERATED_MSGC_FILES} GENERATED PROPERTIES COMPILE_FLAGS -Wall)\n\n"

    x.print "\nSET( ", projName, "_SRCS\n"

    if @customise
      #Do special inclusion of files only found in sourceList returned from
      #readSourceList (IPv6Suite one huge statc executable)
      readSourceList("#{dir}/sourcelist")
      sources.delete_if {|e|
        ret = true
        @sourceList.each{|y|
          if e =~ Regexp.new("#{y}$")
            ret = false
            #Must have been deleting wrong ones as other files were missing (premature optimisation) since some
            #files have similar postfix names
            # @sourceList.delete(y){|z|
            #  $stderr.puts "Unable to remove element #{y} from @sourceList"
            #}
            break
          end
        }
        ret
      }
    end

    #necessary otherwise any subsequent SUBDIRS commands will change
    #the relative source file to an incorrect absolute path
    basepath="${PROJECT_SOURCE_DIR}/"
    
    sources.each{|c| 
      x.puts basepath + c
    }

    x.puts ")"


    x.puts "SET_SOURCE_FILES_PROPERTIES(${#{projName}_SRCS} PROPERTIES  COMPILE_FLAGS -Wall)"
    x.puts "SET(#{projName}_SRCS ${GENERATED_MSGC_FILES} ${#{projName}_SRCS})"
    x.puts
    x.puts

    x.puts "INCLUDE_DIRECTORIES("
    includes.each{|inc|         
      x.puts basepath + inc
    }
    x.puts ")\n\n"

    if not @customise
      outputdir = projName == "INET" ? "Examples/bin" : "."
      x.puts %{SET(OUTPUTDIR #{outputdir}) } 
            
      x.puts(sprintf("ADD_LIBRARY(%s ${%s})\n", projName, projName + "_SRCS"))
      x.puts "SET(#{projName} ${OUTPUTDIR}/#{projName})"
      x.puts "ADD_EXECUTABLE(${#{projName}} ${#{projName}_SRCS})"  
      x.puts %{TARGET_LINK_LIBRARIES(${#{projName}} ${OPP_LIBRARIES} -lstdc++)} # abstract libs
      
      x.puts "SET(tk#{projName} ${OUTPUTDIR}/tk#{projName})"
      x.puts "ADD_EXECUTABLE(${tk#{projName}} ${#{projName}_SRCS})"
      x.puts %{TARGET_LINK_LIBRARIES(${tk#{projName}} ${OPP_TKGUILIBRARIES} -lstdc++)}
    end
  }
end

## main

if ARGV.length < 2 then
  print "Usage ",  " <source dir name> <Project Name>\n", \
  " where [source dir] is where MakeLists.txt will be generated for\n", \
  "Generated in current working directory"
  exit
else
  projName = ARGV[1]
  @customise = projName == "IPv6Suite"
  outname = @customise ? "OneBigStaticExe.cmake" : "CMakeLists.txt"
  writeCMakeList(ARGV[0], outname, projName)
end