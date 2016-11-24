//
//  SAMKeychainQuery.m
//  SAMKeychain
//
//  Created by Caleb Davenport on 3/19/13.
//  Copyright (c) 2013-2014 Sam Soffes. All rights reserved.
//

#import "SAMKeychainQuery.h"
#import "SAMKeychain.h"

@implementation SAMKeychainQuery

@synthesize account = _account;
@synthesize service = _service;
@synthesize label = _label;
@synthesize passwordData = _passwordData;

#ifdef SAMKEYCHAIN_ACCESS_GROUP_AVAILABLE
@synthesize accessGroup = _accessGroup;
#endif

#ifdef SAMKEYCHAIN_SYNCHRONIZATION_AVAILABLE
@synthesize synchronizationMode = _synchronizationMode;
#endif

#pragma mark - Public

/// https://developer.apple.com/library/content/documentation/Security/Conceptual/keychainServConcepts/02concepts/concepts.html#//apple_ref/doc/uid/TP30000897-CH204-TP9

/// 保存
- (BOOL)save:(NSError *__autoreleasing *)error {
	/// 验证service account passwordData 均不能为空
	OSStatus status = SAMKeychainErrorBadArguments;
	if (!self.service || !self.account || !self.passwordData) {
		if (error) {
			*error = [[self class] errorWithCode:status];
		}
		return NO;
	}
	NSMutableDictionary *query = nil;
	
	/// 先查找是否已存在
	/// 已存在的话searchQuery添加kSecValueData:passwordData 调用SecItemUpdate
	/// 不存在的话kSecAttrLabel:self.label kSecValueData:passwordData 调用SecItemAdd
	/// label只在添加的时候有效
	NSMutableDictionary * searchQuery = [self query];
	// retrieve a keychain item’s attributes and/or data.
	status = SecItemCopyMatching((__bridge CFDictionaryRef)searchQuery, nil);
	if (status == errSecSuccess) {//item already exists, update it!
		query = [[NSMutableDictionary alloc]init];
		[query setObject:self.passwordData forKey:(__bridge id)kSecValueData];
#if __IPHONE_4_0 && TARGET_OS_IPHONE
		CFTypeRef accessibilityType = [SAMKeychain accessibilityType];
		if (accessibilityType) {
			[query setObject:(__bridge id)accessibilityType forKey:(__bridge id)kSecAttrAccessible];
		}
#endif
		// modify a keychain item in place
		status = SecItemUpdate((__bridge CFDictionaryRef)(searchQuery), (__bridge CFDictionaryRef)(query));
	}else if(status == errSecItemNotFound){//item not found, create it!
		query = [self query];
		if (self.label) {
			[query setObject:self.label forKey:(__bridge id)kSecAttrLabel];
		}
		[query setObject:self.passwordData forKey:(__bridge id)kSecValueData];
#if __IPHONE_4_0 && TARGET_OS_IPHONE
		CFTypeRef accessibilityType = [SAMKeychain accessibilityType];
		if (accessibilityType) {
			[query setObject:(__bridge id)accessibilityType forKey:(__bridge id)kSecAttrAccessible];
		}
#endif
		// create a new keychain item.
		status = SecItemAdd((__bridge CFDictionaryRef)query, NULL);
	}
	if (status != errSecSuccess && error != NULL) {
		*error = [[self class] errorWithCode:status];
	}
	return (status == errSecSuccess);
}

/// 删除 调用SecItemDelete
- (BOOL)deleteItem:(NSError *__autoreleasing *)error {
	OSStatus status = SAMKeychainErrorBadArguments;
	if (!self.service || !self.account) {
		if (error) {
			*error = [[self class] errorWithCode:status];
		}
		return NO;
	}

	NSMutableDictionary *query = [self query];
#if TARGET_OS_IPHONE
	// remove a keychain item
	status = SecItemDelete((__bridge CFDictionaryRef)query);
#else
	// On Mac OS, SecItemDelete will not delete a key created in a different
	// app, nor in a different version of the same app.
	//
	// To replicate the issue, save a password, change to the code and
	// rebuild the app, and then attempt to delete that password.
	//
	// This was true in OS X 10.6 and probably later versions as well.
	//
	// Work around it by using SecItemCopyMatching and SecKeychainItemDelete.
	CFTypeRef result = NULL;
	[query setObject:@YES forKey:(__bridge id)kSecReturnRef];
	status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
	if (status == errSecSuccess) {
		status = SecKeychainItemDelete((SecKeychainItemRef)result);
		CFRelease(result);
	}
#endif

	if (status != errSecSuccess && error != NULL) {
		*error = [[self class] errorWithCode:status];
	}

	return (status == errSecSuccess);
}

/// kSecReturnAttributes:YES
/// kSecMatchLimit:kSecMatchLimitAll
/// kSecAttrAccessible:
/// 返回结果数组
- (nullable NSArray *)fetchAll:(NSError *__autoreleasing *)error {
	NSMutableDictionary *query = [self query];
	[query setObject:@YES forKey:(__bridge id)kSecReturnAttributes];
	[query setObject:(__bridge id)kSecMatchLimitAll forKey:(__bridge id)kSecMatchLimit];
#if __IPHONE_4_0 && TARGET_OS_IPHONE
	CFTypeRef accessibilityType = [SAMKeychain accessibilityType];
	if (accessibilityType) {
		[query setObject:(__bridge id)accessibilityType forKey:(__bridge id)kSecAttrAccessible];
	}
#endif

	CFTypeRef result = NULL;
	OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
	if (status != errSecSuccess && error != NULL) {
		*error = [[self class] errorWithCode:status];
		return nil;
	}

	return (__bridge_transfer NSArray *)result;
}

/// kSecReturnData:YES
/// kSecMatchLimit:kSecMatchLimitOne
/// service和account不能为空
/// 结果保存在passwordData
- (BOOL)fetch:(NSError *__autoreleasing *)error {
	
	OSStatus status = SAMKeychainErrorBadArguments;
	if (!self.service || !self.account) {
		if (error) {
			*error = [[self class] errorWithCode:status];
		}
		return NO;
	}

	CFTypeRef result = NULL;
	NSMutableDictionary *query = [self query];
	[query setObject:@YES forKey:(__bridge id)kSecReturnData];
	[query setObject:(__bridge id)kSecMatchLimitOne forKey:(__bridge id)kSecMatchLimit];
	status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);

	if (status != errSecSuccess) {
		if (error) {
			*error = [[self class] errorWithCode:status];
		}
		return NO;
	}

	self.passwordData = (__bridge_transfer NSData *)result;
	return YES;
}


#pragma mark - Accessors
/// 设置的值赋给passwordData 并没有save

- (void)setPasswordObject:(id<NSCoding>)object {
	self.passwordData = [NSKeyedArchiver archivedDataWithRootObject:object];
}


- (id<NSCoding>)passwordObject {
	if ([self.passwordData length]) {
		return [NSKeyedUnarchiver unarchiveObjectWithData:self.passwordData];
	}
	return nil;
}


- (void)setPassword:(NSString *)password {
	self.passwordData = [password dataUsingEncoding:NSUTF8StringEncoding];
}


- (NSString *)password {
	if ([self.passwordData length]) {
		return [[NSString alloc] initWithData:self.passwordData encoding:NSUTF8StringEncoding];
	}
	return nil;
}


#pragma mark - Synchronization Status

#ifdef SAMKEYCHAIN_SYNCHRONIZATION_AVAILABLE
+ (BOOL)isSynchronizationAvailable {
#if TARGET_OS_IPHONE
	// Apple suggested way to check for 7.0 at runtime
	// https://developer.apple.com/library/ios/documentation/userexperience/conceptual/transitionguide/SupportingEarlieriOS.html
	return floor(NSFoundationVersionNumber) > NSFoundationVersionNumber_iOS_6_1;
#else
	return floor(NSFoundationVersionNumber) > NSFoundationVersionNumber10_8_4;
#endif
}
#endif


#pragma mark - Private

/// 返回查询条件字典
/// kSecClass:kSecClassGenericPassword
/// kSecAttrService:
/// kSecAttrAccount:
/// kSecAttrAccessGroup:这个不一定有
/// kSecAttrSynchronizable:
- (NSMutableDictionary *)query {
	NSMutableDictionary *dictionary = [NSMutableDictionary dictionaryWithCapacity:3];
	[dictionary setObject:(__bridge id)kSecClassGenericPassword forKey:(__bridge id)kSecClass];

	if (self.service) {
		[dictionary setObject:self.service forKey:(__bridge id)kSecAttrService];
	}

	if (self.account) {
		[dictionary setObject:self.account forKey:(__bridge id)kSecAttrAccount];
	}

#ifdef SAMKEYCHAIN_ACCESS_GROUP_AVAILABLE
#if !TARGET_IPHONE_SIMULATOR
	if (self.accessGroup) {
		[dictionary setObject:self.accessGroup forKey:(__bridge id)kSecAttrAccessGroup];
	}
#endif
#endif

#ifdef SAMKEYCHAIN_SYNCHRONIZATION_AVAILABLE
	if ([[self class] isSynchronizationAvailable]) {
		id value;

		switch (self.synchronizationMode) {
			case SAMKeychainQuerySynchronizationModeNo: {
			  value = @NO;
			  break;
			}
			case SAMKeychainQuerySynchronizationModeYes: {
			  value = @YES;
			  break;
			}
			case SAMKeychainQuerySynchronizationModeAny: {
			  value = (__bridge id)(kSecAttrSynchronizableAny);
			  break;
			}
		}

		[dictionary setObject:value forKey:(__bridge id)(kSecAttrSynchronizable)];
	}
#endif

	return dictionary;
}

/// 根据code返回NSError
+ (NSError *)errorWithCode:(OSStatus) code {
	static dispatch_once_t onceToken;
	static NSBundle *resourcesBundle = nil;
	dispatch_once(&onceToken, ^{
		NSURL *url = [[NSBundle bundleForClass:[SAMKeychainQuery class]] URLForResource:@"SAMKeychain" withExtension:@"bundle"];
		resourcesBundle = [NSBundle bundleWithURL:url];
	});
	
	NSString *message = nil;
	switch (code) {
		case errSecSuccess: return nil;
		case SAMKeychainErrorBadArguments: message = NSLocalizedStringFromTableInBundle(@"SAMKeychainErrorBadArguments", @"SAMKeychain", resourcesBundle, nil); break;

#if TARGET_OS_IPHONE
		case errSecUnimplemented: {
			message = NSLocalizedStringFromTableInBundle(@"errSecUnimplemented", @"SAMKeychain", resourcesBundle, nil);
			break;
		}
		case errSecParam: {
			message = NSLocalizedStringFromTableInBundle(@"errSecParam", @"SAMKeychain", resourcesBundle, nil);
			break;
		}
		case errSecAllocate: {
			message = NSLocalizedStringFromTableInBundle(@"errSecAllocate", @"SAMKeychain", resourcesBundle, nil);
			break;
		}
		case errSecNotAvailable: {
			message = NSLocalizedStringFromTableInBundle(@"errSecNotAvailable", @"SAMKeychain", resourcesBundle, nil);
			break;
		}
		case errSecDuplicateItem: {
			message = NSLocalizedStringFromTableInBundle(@"errSecDuplicateItem", @"SAMKeychain", resourcesBundle, nil);
			break;
		}
		case errSecItemNotFound: {
			message = NSLocalizedStringFromTableInBundle(@"errSecItemNotFound", @"SAMKeychain", resourcesBundle, nil);
			break;
		}
		case errSecInteractionNotAllowed: {
			message = NSLocalizedStringFromTableInBundle(@"errSecInteractionNotAllowed", @"SAMKeychain", resourcesBundle, nil);
			break;
		}
		case errSecDecode: {
			message = NSLocalizedStringFromTableInBundle(@"errSecDecode", @"SAMKeychain", resourcesBundle, nil);
			break;
		}
		case errSecAuthFailed: {
			message = NSLocalizedStringFromTableInBundle(@"errSecAuthFailed", @"SAMKeychain", resourcesBundle, nil);
			break;
		}
		default: {
			message = NSLocalizedStringFromTableInBundle(@"errSecDefault", @"SAMKeychain", resourcesBundle, nil);
		}
#else
		default:
			message = (__bridge_transfer NSString *)SecCopyErrorMessageString(code, NULL);
#endif
	}

	NSDictionary *userInfo = nil;
	if (message) {
		userInfo = @{ NSLocalizedDescriptionKey : message };
	}
	return [NSError errorWithDomain:kSAMKeychainErrorDomain code:code userInfo:userInfo];
}

@end
