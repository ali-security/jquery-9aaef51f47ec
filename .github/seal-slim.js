// The 1.12.3 npm package ships a stray jQuery 3.0.0-beta1 slim build
// (dist/jquery.slim.js, .min.js, .min.map) from jquery-dist's 086d381c, which
// the release published as-is and grunt never rebuilds. This Gruntfile ports
// the sealed CVE fixes into that jquery.slim.js, as upstream wrote them for
// 3.x, and re-minifies it with this release's uglify options; the banner is the
// first line of the published jquery.slim.min.js. Both slim files are then
// loaded in jsdom and every check must find its attack in the files as
// published and find it closed in the sealed ones.
// Each sealed CVE adds its own delimited entries to `fixes` (exact string
// replacements, each must match exactly once) and to `checks`.
// Usage: grunt --gruntfile .github/seal-slim.js --base . --dist=<dir>
var fs = require( "fs" ),
	path = require( "path" );

module.exports = function( grunt ) {
	var dist = grunt.option( "dist" ),
		srcLoc = dist + "/jquery.slim.js",
		minLoc = dist + "/jquery.slim.min.js",
		files = {},
		fixes = [

			// CVE-2020-11022 (upstream 1d61fd9): htmlPrefilter is the identity
			[
				"\trxhtmlTag = /<(?!area|br|col|embed|hr|img|input|link|meta|param)" +
				"(([a-z][^\\/\\0>\\x20\\t\\r\\n\\f]*)[^>]*)\\/>/gi,\n",

				""
			],
			[
				"\t\treturn html.replace( rxhtmlTag, \"<$1></$2>\" );\n",

				"\t\treturn html;\n"
			],

			// CVE-2020-11023 (upstream 1d61fd9, 966a709): wrap <option> and
			// <optgroup> in <select multiple> only where IE <=9 needs it. The
			// wrapMap is defined above the support probe in this build, so the
			// conditional wrapper goes after the probe.
			[
				"var wrapMap = {\n" +
				"\n" +
				"\t// Support: IE9\n" +
				"\toption: [ 1, \"<select multiple='multiple'>\", \"</select>\" ],\n" +
				"\n",

				"var wrapMap = {\n" +
				"\n"
			],
			[
				"// Support: IE9\n" +
				"wrapMap.optgroup = wrapMap.option;\n" +
				"\n",

				""
			],
			[
				"\tsupport.noCloneChecked = !!div.cloneNode( true ).lastChild.defaultValue;\n" +
				"} )();\n",

				"\tsupport.noCloneChecked = !!div.cloneNode( true ).lastChild.defaultValue;\n" +
				"\n" +
				"\t// Support: IE <=9 only\n" +
				"\t// IE <=9 replaces <option> tags with their contents when inserted outside of\n" +
				"\t// the select element.\n" +
				"\tdiv.innerHTML = \"<option></option>\";\n" +
				"\tsupport.option = !!div.lastChild;\n" +
				"} )();\n" +
				"\n" +
				"// Support: IE <=9 only\n" +
				"// IE <=9 replaces <option> tags with their contents when inserted outside of\n" +
				"// the select element.\n" +
				"if ( !support.option ) {\n" +
				"\twrapMap.optgroup = wrapMap.option = [ 1, \"<select multiple='multiple'>\", \"</select>\" ];\n" +
				"}\n"
			],

			// CVE-2019-11358 (upstream 753d591)
			[
				"\t\t\t\t// Prevent never-ending loop\n" +
				"\t\t\t\tif ( target === copy ) {\n",

				"\t\t\t\t// Prevent Object.prototype pollution\n" +
				"\t\t\t\t// Prevent never-ending loop\n" +
				"\t\t\t\tif ( name === \"__proto__\" || target === copy ) {\n"
			],

			// CVE-2016-10707 (upstream e06fda6): key the attrHandle swap by the
			// lowercase name
			[
				"\t\tvar ret, handle;\n" +
				"\t\tif ( !isXML ) {\n" +
				"\n" +
				"\t\t\t// Avoid an infinite loop by temporarily removing this function from the getter\n" +
				"\t\t\thandle = attrHandle[ name ];\n" +
				"\t\t\tattrHandle[ name ] = ret;\n" +
				"\t\t\tret = getter( elem, name, isXML ) != null ?\n" +
				"\t\t\t\tname.toLowerCase() :\n" +
				"\t\t\t\tnull;\n" +
				"\t\t\tattrHandle[ name ] = handle;\n",

				"\t\tvar ret, handle,\n" +
				"\t\t\tlowercaseName = name.toLowerCase();\n" +
				"\n" +
				"\t\tif ( !isXML ) {\n" +
				"\n" +
				"\t\t\t// Avoid an infinite loop by temporarily removing this function from the getter\n" +
				"\t\t\thandle = attrHandle[ lowercaseName ];\n" +
				"\t\t\tattrHandle[ lowercaseName ] = ret;\n" +
				"\t\t\tret = getter( elem, name, isXML ) != null ?\n" +
				"\t\t\t\tlowercaseName :\n" +
				"\t\t\t\tnull;\n" +
				"\t\t\tattrHandle[ lowercaseName ] = handle;\n"
			]
		],
		checks = [

			// CVE-2020-11022: HTML that is inert as the browser itself parses it
			// (the Cure53 payloads of upstream's "Sanitized HTML doesn't get
			// unsanitized" test) must not grow an onerror handler when it goes
			// through jQuery's manipulation methods.
			{
				name: "CVE-2020-11022",
				run: function( jQuery, document ) {
					var problems = [];

					[
						"<img alt=\"<x\" title=\"/><img src=url404 onerror=xss(0)>\">",
						"<img alt=\"\n<x\" title=\"/>\n<img src=url404 onerror=xss(1)>\">",
						"<style><style/><img src=url404 onerror=xss(2)>",
						"<xmp><xmp/><img src=url404 onerror=xss(3)>",
						"<title><title /><img src=url404 onerror=xss(4)>",
						"<iframe><iframe/><img src=url404 onerror=xss(5)>",
						"<noframes><noframes/><img src=url404 onerror=xss(6)>",
						"<noscript><noscript/><img src=url404 onerror=xss(7)>",
						"<foo\" alt=\"\" title=\"/><img src=url404 onerror=xss(8)>\">",
						"<img alt=\"<x\" title=\"\" src=\"/><img src=url404 onerror=xss(9)>\">",
						"<noscript/><img src=url404 onerror=xss(10)>",
						"<noembed><noembed/><img src=url404 onerror=xss(11)>"
					].forEach( function( html ) {
						var parsed = document.createElement( "div" ),
							inert;

						parsed.innerHTML = html;
						inert = countOnerror( parsed );

						if ( jQuery.htmlPrefilter( html ) !== html ) {
							problems.push( "htmlPrefilter rewrote " + JSON.stringify( html ) +
								" to " + JSON.stringify( jQuery.htmlPrefilter( html ) ) );
						}
						if ( countOnerror( jQuery( "<div></div>" ).html( html )[ 0 ] ) > inert ) {
							problems.push( ".html() created an onerror handler from " +
								JSON.stringify( html ) );
						}
						if ( countOnerror( jQuery( "<div></div>" ).append( html )[ 0 ] ) > inert ) {
							problems.push( ".append() created an onerror handler from " +
								JSON.stringify( html ) );
						}
					} );

					return problems;
				}
			},

			// CVE-2020-11023: <option> must be parsed in place, not inside a
			// <select> wrapper that a stray "</select>" in the input closes early,
			// pushing the rest of the markup out of the wrapper (upstream's gh-4647
			// test and the Cure53 <option><style> payload of its "Sanitized HTML
			// doesn't get unsanitized" test).
			{
				name: "CVE-2020-11023",
				run: function( jQuery ) {
					var problems = [];

					[
						[ "<option>a</option></select><b>b</b>", [ "option", "b" ] ],
						[
							"<option><style></option></select><img src=url404 onerror=xss(11)></style>",
							[ "option" ]
						]
					].forEach( function( test ) {
						var html = test[ 0 ],
							expected = JSON.stringify( test[ 1 ] );

						[
							[ "jQuery(html)", function() {
								return jQuery( html );
							} ],
							[ "jQuery.parseHTML()", function() {
								return jQuery.parseHTML( html );
							} ],
							[ ".html()", function() {
								return jQuery( "<div></div>" ).html( html )[ 0 ].childNodes;
							} ],
							[ ".append()", function() {
								return jQuery( "<div></div>" ).append( html )[ 0 ].childNodes;
							} ]
						].forEach( function( method ) {
							var names = JSON.stringify( nodeNames( method[ 1 ]() ) );

							if ( names !== expected ) {
								problems.push( method[ 0 ] + " parsed " + JSON.stringify( html ) +
									" into " + names + ", not " + expected );
							}
						} );
					} );

					return problems;
				}
			},

			// CVE-2019-11358: a deep jQuery.extend() of parsed JSON that carries an
			// own "__proto__" key (upstream's "jQuery.extend( true, ... )
			// Object.prototype pollution" test) must not write into
			// Object.prototype. jQuery is require()d, so its own object literals
			// belong to node's realm, and so do jsdom 5's window and DOM objects
			// (window.Object is node's Object or absent): node's Object.prototype
			// is the one this attack reaches. Should the window carry an Object of
			// a realm of its own, the attack is also run with a target and JSON of
			// that realm; the Object.prototype of every realm is checked (and
			// cleaned) after each run.
			{
				name: "CVE-2019-11358",
				run: function( jQuery, document, window ) {
					var problems = [],
						json = "{\"__proto__\": {\"devMode\": true}}",
						realms = [ { name: "node", Object: Object, JSON: JSON } ];

					if ( typeof window.Object === "function" && window.Object !== Object &&
						window.JSON ) {
						realms.push( { name: "window", Object: window.Object, JSON: window.JSON } );
					}

					realms.forEach( function( attack ) {
						var payload = attack.JSON.parse( json );

						if ( !Object.prototype.hasOwnProperty.call( payload, "__proto__" ) ) {
							grunt.fail.fatal( "CVE-2019-11358 check: " + attack.name +
								" JSON.parse gave no own \"__proto__\" key" );
						}
						jQuery.extend( true, new attack.Object(), payload );

						realms.forEach( function( realm ) {
							if ( "devMode" in new realm.Object() ) {
								problems.push( "jQuery.extend( true, " + attack.name + " {}, " +
									attack.name + " JSON.parse( " + JSON.stringify( json ) +
									" ) ) polluted the " + realm.name + " Object.prototype" );
							}
							delete realm.Object.prototype.devMode;
						} );
					} );

					return problems;
				}
			},

			// CVE-2016-10707: reading a boolean attribute by a name that is not
			// all lowercase (upstream's "non-lowercase boolean attribute getters
			// should not crash" test) must not crash. Sizzle looks the handler up
			// by the lowercase name, so a wrapper that only swaps out
			// attrHandle[ name ] calls itself until the stack overflows.
			{
				name: "CVE-2016-10707",
				run: function( jQuery, document ) {
					var problems = [],
						elem = jQuery( "<input disabled required autofocus type='checkbox'>" )
							.appendTo( document.body );

					jQuery.each( {
						disabled: "DisAbled",
						required: "requiRed",
						autofocus: "AUTOFOCUS"
					}, function( lowercased, original ) {
						[
							[ ".attr( \"" + original + "\" )", lowercased, function() {
								return elem.attr( original );
							} ],
							[ "jQuery.find.attr( elem, \"" + original + "\" )", lowercased, function() {
								return jQuery.find.attr( elem[ 0 ], original );
							} ],
							[ ".filter( \"[" + original + "]\" ).length", 1, function() {
								return elem.filter( "[" + original + "]" ).length;
							} ]
						].forEach( function( getter ) {
							var value;

							try {
								value = getter[ 2 ]();
							} catch ( e ) {
								problems.push( getter[ 0 ] + " threw " + e );
								return;
							}
							if ( value !== getter[ 1 ] ) {
								problems.push( getter[ 0 ] + " returned " + JSON.stringify( value ) +
									", not " + JSON.stringify( getter[ 1 ] ) );
							}
						} );
					} );

					elem.remove();
					return problems;
				}
			}
		];

	// Number of elements under elem that carry an onerror attribute
	function countOnerror( elem ) {
		var all = elem.getElementsByTagName( "*" ),
			count = 0,
			i;

		for ( i = 0; i < all.length; i++ ) {
			if ( all[ i ].hasAttribute( "onerror" ) ) {
				count++;
			}
		}
		return count;
	}

	// Lowercase nodeNames of an array-like list of nodes
	function nodeNames( nodes ) {
		var names = [],
			i;

		for ( i = 0; i < nodes.length; i++ ) {
			names.push( nodes[ i ].nodeName.toLowerCase() );
		}
		return names;
	}

	files[ minLoc ] = [ srcLoc ];

	grunt.initConfig( {
		uglify: {
			slim: {
				files: files,
				options: {
					preserveComments: false,
					sourceMap: true,
					sourceMapName: dist + "/jquery.slim.min.map",
					report: "min",
					beautify: {
						"ascii_only": true
					},
					banner: fs.readFileSync( minLoc, "utf8" ).split( "\n" )[ 0 ],
					compress: {
						"hoist_funs": false,
						loops: false,
						unused: false
					}
				}
			}
		}
	} );

	grunt.loadNpmTasks( "grunt-contrib-uglify" );

	grunt.registerTask( "seal_patch_slim", function() {
		var text = fs.readFileSync( srcLoc, "utf8" );
		fixes.forEach( function( fix, i ) {
			if ( text.split( fix[ 0 ] ).length !== 2 ) {
				grunt.fail.fatal( "slim fix " + i + " does not match exactly once" );
			}
			text = text.replace( fix[ 0 ], function() {
				return fix[ 1 ];
			} );
		} );
		fs.writeFileSync( srcLoc, text );
		grunt.log.ok( fixes.length + " slim fixes applied to " + srcLoc );
	} );

	// As this release's remove_map_comment task (build/tasks/sourcemap.js)
	grunt.registerTask( "remove_map_comment", function() {
		var text = fs.readFileSync( minLoc, "utf8" )
			.replace( /\/\/# sourceMappingURL=\S+/, "" );
		fs.writeFileSync( minLoc, text );
	} );

	// Loads jquery.slim.js and jquery.slim.min.js, each in its own jsdom window,
	// and runs every check on them.
	// seal_check_slim:unpatched - every check must reproduce its attack on the
	//   files as published (so it really exercises the vulnerability)
	// seal_check_slim:sealed - every check must pass on the sealed files
	grunt.registerTask( "seal_check_slim", function( mode ) {
		var done = this.async(),
			queue = [ srcLoc, minLoc ];

		function next() {
			var file = queue.shift();

			if ( !file ) {
				return done();
			}
			require( "jsdom" ).env( "", function( errors, window ) {
				var resolved = path.resolve( file ),
					jQuery;

				if ( errors ) {
					grunt.fail.fatal( "jsdom: " + errors );
				}
				delete require.cache[ resolved ];
				jQuery = require( resolved )( window );
				if ( !/^jQuery/.test( jQuery.expando ) ) {
					grunt.fail.fatal( "could not load jQuery from " + file );
				}

				checks.forEach( function( check ) {
					var problems = check.run( jQuery, window.document, window );

					if ( mode === "unpatched" ) {
						if ( !problems.length ) {
							grunt.fail.fatal( check.name + " check does not reproduce on the " +
								"unpatched " + file );
						}
						grunt.log.writeln( check.name + " reproduces on the unpatched " + file + ":" );
					} else if ( problems.length ) {
						grunt.log.error( check.name + " is still open in " + file + ":" );
					}
					problems.forEach( function( problem ) {
						grunt.log.writeln( "  " + problem );
					} );
					if ( mode !== "unpatched" ) {
						if ( problems.length ) {
							grunt.fail.fatal( check.name + " check failed on " + file );
						}
						grunt.log.ok( check.name + " check passed on " + file );
					}
				} );

				window.close();
				next();
			} );
		}

		next();
	} );

	grunt.registerTask( "default", [
		"seal_check_slim:unpatched",
		"seal_patch_slim",
		"uglify",
		"remove_map_comment",
		"seal_check_slim:sealed"
	] );
};
